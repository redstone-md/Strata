//! Persisted job queue (`jobs` table): what was asked, how far it got and where it resumes.
//! The meaning of `kind`, `state` and `checkpoint` belongs to the application layer; the case
//! only stores them.

use crate::Case;
use crate::case::now;
use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: u32,
    /// First job of the pipeline this job belongs to (`None` for a single step).
    pub pipeline: Option<u32>,
    pub evidence: EvidenceId,
    pub kind: String,
    pub title: String,
    pub state: String,
    /// Summary when done, reason when failed.
    pub detail: String,
    pub created_at: i64,
    /// Start of the latest run (a resumed job restarts its clock).
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// Step-specific resume point (JSON).
    pub checkpoint: Option<String>,
    pub done: u64,
    pub total: u64,
    /// Process that ran the job last.
    pub owner_pid: Option<u32>,
    /// Unix seconds of the last state or checkpoint write.
    pub updated_at: i64,
}

/// Timestamp written along with a state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStamp {
    /// Started (or resumed) by process `pid`.
    Started { pid: u32 },
    /// Queued again by process `pid`, which now owns it.
    Claimed { pid: u32 },
    Finished,
    None,
}

const COLUMNS: &str = "id, pipeline, evidence_id, kind, title, state, detail, created_at, started_at, finished_at,
                       checkpoint, done, total, owner_pid, updated_at";

fn record(r: &Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: r.get(0)?,
        pipeline: r.get(1)?,
        evidence: EvidenceId::new(r.get(2)?),
        kind: r.get(3)?,
        title: r.get(4)?,
        state: r.get(5)?,
        detail: r.get(6)?,
        created_at: r.get(7)?,
        started_at: r.get(8)?,
        finished_at: r.get(9)?,
        checkpoint: r.get(10)?,
        done: r.get::<_, i64>(11)?.max(0) as u64,
        total: r.get::<_, i64>(12)?.max(0) as u64,
        owner_pid: r.get(13)?,
        updated_at: r.get(14)?,
    })
}

impl Case {
    /// Queue a job owned by process `owner`; returns its id (stable across restarts).
    pub fn add_job(&self, owner: u32, evidence: EvidenceId, kind: &str, title: &str, state: &str) -> Result<u32> {
        self.with_conn(|conn| {
            let t = now();
            conn.execute(
                "INSERT INTO jobs (evidence_id, kind, title, state, owner_pid, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![evidence.get(), kind, title, state, owner, t],
            )?;
            Ok(conn.last_insert_rowid() as u32)
        })
    }

    /// Put jobs into one pipeline (the first job's id).
    pub fn set_job_pipeline(&self, ids: &[u32], pipeline: u32) -> Result<()> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            for id in ids {
                tx.execute("UPDATE jobs SET pipeline = ?2 WHERE id = ?1", params![id, pipeline])?;
            }
            tx.commit()
        })
    }

    pub fn update_job(&self, id: u32, state: &str, detail: &str, stamp: JobStamp) -> Result<()> {
        self.with_conn(|conn| {
            let t = now();
            match stamp {
                JobStamp::Started { pid } => conn.execute(
                    "UPDATE jobs SET state = ?2, detail = ?3, started_at = ?4, finished_at = NULL,
                     owner_pid = ?5, updated_at = ?4 WHERE id = ?1",
                    params![id, state, detail, t, pid],
                ),
                JobStamp::Claimed { pid } => conn.execute(
                    "UPDATE jobs SET state = ?2, detail = ?3, owner_pid = ?5, updated_at = ?4 WHERE id = ?1",
                    params![id, state, detail, t, pid],
                ),
                JobStamp::Finished => conn.execute(
                    "UPDATE jobs SET state = ?2, detail = ?3, finished_at = ?4, updated_at = ?4 WHERE id = ?1",
                    params![id, state, detail, t],
                ),
                JobStamp::None => conn.execute(
                    "UPDATE jobs SET state = ?2, detail = ?3, updated_at = ?4 WHERE id = ?1",
                    params![id, state, detail, t],
                ),
            }
            .map(|_| ())
        })
    }

    /// Progress without a checkpoint (steps that have nothing to resume).
    pub fn job_progress(&self, id: u32, done: u64, total: u64) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE jobs SET done = ?2, total = ?3, updated_at = ?4 WHERE id = ?1",
                params![id, done as i64, total as i64, now()],
            )
            .map(|_| ())
        })
    }

    /// The most recent `limit` jobs, oldest first.
    pub fn jobs(&self, limit: usize) -> Result<Vec<JobRecord>> {
        self.with_conn(|conn| {
            let sql = format!("SELECT * FROM (SELECT {COLUMNS} FROM jobs ORDER BY id DESC LIMIT ?1) ORDER BY id");
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([limit as i64], record)?;
            rows.collect()
        })
    }

    pub fn job(&self, id: u32) -> Result<Option<JobRecord>> {
        self.with_conn(|conn| {
            conn.query_row(&format!("SELECT {COLUMNS} FROM jobs WHERE id = ?1"), [id], record).optional()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_keep_ids_state_and_checkpoint_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("j.strata");
        let ev = EvidenceId::new(1);
        {
            let case = Case::open(&root).unwrap();
            let a = case.add_job(3, ev, "Scan", "Deep scan", "Queued").unwrap();
            let b = case.add_job(3, ev, "Carve", "Carve", "Queued").unwrap();
            case.set_job_pipeline(&[a, b], a).unwrap();
            case.update_job(a, "Running", "", JobStamp::Started { pid: 7 }).unwrap();
            case.write(|w| w.job_checkpoint(a, r#"{"at":5}"#, 5, 10)).unwrap();
            // A failing unit of work leaves the checkpoint as it was.
            let failed: Result<()> = case.write(|w| {
                w.job_checkpoint(a, r#"{"at":9}"#, 9, 10)?;
                Err(strata_kernel::Error::Other("crash".into()))
            });
            assert!(failed.is_err());
        }
        let case = Case::open(&root).unwrap();
        let jobs = case.jobs(10).unwrap();
        assert_eq!(jobs.len(), 2);
        let a = &jobs[0];
        assert_eq!((a.state.as_str(), a.owner_pid, a.pipeline), ("Running", Some(7), Some(a.id)));
        assert_eq!((a.checkpoint.as_deref(), a.done, a.total), (Some(r#"{"at":5}"#), 5, 10));
        assert!(a.started_at.is_some() && a.finished_at.is_none());
        case.update_job(a.id, "Done", "ok", JobStamp::Finished).unwrap();
        assert!(case.job(a.id).unwrap().unwrap().finished_at.is_some());
        assert_eq!(case.jobs(1).unwrap()[0].id, jobs[1].id, "limit keeps the newest");
    }
}
