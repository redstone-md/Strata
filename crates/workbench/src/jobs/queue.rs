//! The job list of one open case, mirrored in the case's `jobs` table: ids are row ids, so
//! they survive restarts; state changes are written through; jobs left queued or running by
//! a process that is gone come back as interrupted.

use super::context::Faults;
use super::{Checkpoint, Job, JobId, JobKind, JobState, JobTimes};
use crate::monitor::is_strata_process;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use strata_case::{Case, JobRecord, JobStamp};
use strata_kernel::{EvidenceId, Result};

/// Jobs loaded from the case when it opens.
const HISTORY: usize = 500;

#[derive(Default)]
pub(crate) struct JobQueue {
    jobs: Mutex<Vec<Arc<Job>>>,
    pub faults: Faults,
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

impl JobQueue {
    /// Jobs of the case; unfinished ones whose process is gone become interrupted.
    pub fn load(case: &Case) -> Result<Self> {
        let me = std::process::id();
        let mut jobs = Vec::new();
        for r in case.jobs(HISTORY)? {
            let Some(job) = Self::restore(&r) else { continue };
            let mut job = job;
            if job.state.lock().is_active() {
                match r.owner_pid.filter(|pid| *pid != me && is_strata_process(*pid)) {
                    Some(pid) => job.foreign = Some(pid),
                    None => {
                        *job.state.lock() = JobState::Interrupted;
                        case.update_job(r.id, "Interrupted", "", JobStamp::None)?;
                    }
                }
            }
            jobs.push(Arc::new(job));
        }
        Ok(Self { jobs: Mutex::new(jobs), faults: Faults::default() })
    }

    fn restore(r: &JobRecord) -> Option<Job> {
        let kind = JobKind::parse(&r.kind)?;
        let job = Job::new(JobId(r.id), kind, r.evidence, r.pipeline.map(JobId), JobState::from_record(&r.state, &r.detail));
        job.control.begin_at(r.done, r.total);
        let json = r.checkpoint.as_deref().and_then(|c| serde_json::from_str(c).ok());
        let saved_at = json.as_ref().map(|_| r.updated_at);
        *job.checkpoint.lock() = Checkpoint { json, saved_at };
        *job.times.lock() = JobTimes { created: r.created_at, started: r.started_at, finished: r.finished_at };
        Some(job)
    }

    /// Queue jobs of `kinds` as one pipeline (a single kind is a lone step).
    pub fn enqueue(&self, case: &Case, evidence: EvidenceId, kinds: &[JobKind]) -> Result<Vec<Arc<Job>>> {
        let mut ids = Vec::new();
        for kind in kinds {
            ids.push(case.add_job(std::process::id(), evidence, kind.name(), &kind.title(evidence), "Queued")?);
        }
        let pipeline = (ids.len() > 1).then(|| ids[0]);
        if let Some(p) = pipeline {
            case.set_job_pipeline(&ids, p)?;
        }
        let created = unix_now();
        let jobs: Vec<Arc<Job>> = kinds
            .iter()
            .zip(&ids)
            .map(|(kind, id)| {
                let job = Job::new(JobId(*id), *kind, evidence, pipeline.map(JobId), JobState::Queued);
                job.times.lock().created = created;
                Arc::new(job)
            })
            .collect();
        self.jobs.lock().extend(jobs.iter().cloned());
        Ok(jobs)
    }

    pub fn all(&self) -> Vec<Arc<Job>> {
        self.jobs.lock().clone()
    }

    pub fn get(&self, id: JobId) -> Option<Arc<Job>> {
        self.jobs.lock().iter().find(|j| j.id == id).cloned()
    }

    pub fn has_active(&self) -> bool {
        self.jobs.lock().iter().any(|j| j.is_active())
    }

    /// Interrupted jobs grouped by pipeline, each group in run order.
    pub fn interrupted(&self) -> Vec<Vec<Arc<Job>>> {
        let mut groups: Vec<(JobId, Vec<Arc<Job>>)> = Vec::new();
        for job in self.jobs.lock().iter().filter(|j| j.foreign.is_none() && *j.state.lock() == JobState::Interrupted) {
            let key = job.pipeline.unwrap_or(job.id);
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, g)) => g.push(job.clone()),
                None => groups.push((key, vec![job.clone()])),
            }
        }
        groups
            .into_iter()
            .map(|(_, mut g)| {
                g.sort_by_key(|j| j.id);
                g
            })
            .collect()
    }

    /// Change a job's state in memory and in the case (unless the process "died" in a test).
    pub fn set_state(&self, case: &Case, job: &Job, state: JobState) {
        let now = unix_now();
        let stamp = {
            let mut times = job.times.lock();
            match &state {
                JobState::Running => {
                    times.started.get_or_insert(now);
                    times.finished = None;
                    JobStamp::Started { pid: std::process::id() }
                }
                JobState::Done(_) | JobState::Failed(_) | JobState::Cancelled => {
                    times.finished = Some(now);
                    JobStamp::Finished
                }
                JobState::Queued => JobStamp::Claimed { pid: std::process::id() },
                JobState::Interrupted => JobStamp::None,
            }
        };
        if !self.faults.is_dead() {
            let (name, detail) = state.to_record();
            // A failed status write must not stop the work; the next write retries the state.
            let _ = case.update_job(job.id.0, name, detail, stamp);
            if stamp == JobStamp::Finished {
                let p = job.control.snapshot();
                let _ = case.job_progress(job.id.0, p.scanned, p.total);
            }
        }
        *job.state.lock() = state;
    }
}
