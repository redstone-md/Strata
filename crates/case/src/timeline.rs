//! Timeline and host facts persistence.

use crate::Case;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_timeline::TimelineEvent;

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub evidence: Option<EvidenceId>,
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
    pub text: Option<String>,
    pub crypto_only: bool,
    /// Leave out bulk filesystem MACB events.
    pub skip_filesystem: bool,
    pub limit: usize,
    pub offset: usize,
}

/// A host fact (computer name, user profile, USB device, wallet data dir...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFact {
    pub evidence: EvidenceId,
    /// Volume the fact was read from (`None` in cases made before volumes were recorded).
    #[serde(default)]
    pub volume: Option<u32>,
    pub key: String,
    pub value: String,
    pub artifact: String,
    pub source: String,
}

impl Case {
    pub fn store_events(&self, id: EvidenceId, events: &[TimelineEvent]) -> Result<usize> {
        self.write(|w| w.events(id, events))
    }

    pub fn events(&self, q: &EventQuery) -> Result<Vec<(EvidenceId, TimelineEvent)>> {
        let mut sql = String::from("SELECT evidence_id, data FROM events WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        // `{n}` in the clause becomes the index of the argument just pushed.
        let mut filter = |clause: &str, value: Box<dyn rusqlite::ToSql>| {
            args.push(value);
            sql += &clause.replace("{n}", &args.len().to_string());
        };
        if let Some(e) = q.evidence {
            filter(" AND evidence_id = ?{n}", Box::new(e.get()));
        }
        if let Some(t) = q.from {
            filter(" AND at >= ?{n}", Box::new(t.unix_micros()));
        }
        if let Some(t) = q.to {
            filter(" AND at < ?{n}", Box::new(t.unix_micros()));
        }
        if let Some(t) = q.text.as_ref().filter(|t| !t.is_empty()) {
            filter(" AND (title LIKE ?{n} OR path LIKE ?{n})", Box::new(format!("%{t}%")));
        }
        if q.crypto_only {
            sql += " AND crypto = 1";
        }
        if q.skip_filesystem {
            sql += " AND artifact NOT LIKE 'fs.%'";
        }
        sql += " ORDER BY at";
        if q.limit > 0 {
            sql += &format!(" LIMIT {} OFFSET {}", q.limit, q.offset);
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
                Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(e, data)| Some((EvidenceId::new(e), serde_json::from_str(&data).ok()?)))
                .collect())
        })
    }

    /// Events per UTC day: `(day start, total, crypto-tagged)`, filesystem events excluded.
    pub fn events_per_day(&self, evidence: Option<EvidenceId>) -> Result<Vec<(Timestamp, u64, u64)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT at / 86400000000, COUNT(*), SUM(crypto) FROM events
                 WHERE (?1 IS NULL OR evidence_id = ?1) AND artifact NOT LIKE 'fs.%' GROUP BY 1 ORDER BY 1",
            )?;
            let rows = stmt.query_map([evidence.map(|e| e.get())], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(day, n, c)| Some((Timestamp::from_unix_secs(day * 86_400)?, n, c)))
                .collect())
        })
    }

    pub fn facts(&self, evidence: Option<EvidenceId>) -> Result<Vec<HostFact>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT evidence_id, key, value, artifact, source, volume FROM facts WHERE (?1 IS NULL OR evidence_id = ?1) ORDER BY key",
            )?;
            let rows = stmt.query_map([evidence.map(|e| e.get())], |r| {
                Ok(HostFact {
                    evidence: EvidenceId::new(r.get(0)?),
                    key: r.get(1)?,
                    value: r.get(2)?,
                    artifact: r.get(3)?,
                    source: r.get(4)?,
                    volume: r.get(5)?,
                })
            })?;
            rows.collect()
        })
    }
}

pub(crate) fn insert_events(conn: &Connection, id: EvidenceId, volume: Option<u32>, events: &[TimelineEvent]) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO events (evidence_id, at, kind, title, artifact, path, deleted, crypto, data, volume)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?;
    for e in events {
        stmt.execute(params![
            id.get(),
            e.at().unix_micros(),
            format!("{:?}", e.kind()),
            e.title(),
            e.source().artifact,
            e.source().path,
            e.source().deleted,
            e.is_crypto(),
            serde_json::to_string(e).unwrap_or_default(),
            volume,
        ])?;
    }
    Ok(events.len())
}

pub(crate) fn insert_facts(conn: &Connection, facts: &[HostFact]) -> rusqlite::Result<()> {
    let mut stmt =
        conn.prepare_cached("INSERT INTO facts (evidence_id, key, value, artifact, source, volume) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
    for f in facts {
        stmt.execute(params![f.evidence.get(), f.key, f.value, f.artifact, f.source, f.volume])?;
    }
    Ok(())
}

impl crate::Case {
    /// Repair event titles and details stored through the wrong code page by versions that did
    /// not undo it while reading (see [`strata_accounts::repair_mojibake`]). Only rows holding
    /// the tell-tale `Р`/`С` lead letters are read. Returns the rows changed.
    pub fn repair_event_text(&self) -> strata_kernel::Result<usize> {
        let rows: Vec<(i64, String, String)> = self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT id, title, data FROM events WHERE title GLOB '*[РС]*' OR data GLOB '*[РС]*'")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
        })?;
        let fixed: Vec<(i64, String, String)> = rows
            .into_iter()
            .filter_map(|(id, title, data)| {
                let t = strata_accounts::repair_mojibake(&title).into_owned();
                let d = strata_accounts::repair_mojibake(&data).into_owned();
                (t != title || d != data).then_some((id, t, d))
            })
            .collect();
        self.with_write(|conn| {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare("UPDATE events SET title = ?2, data = ?3 WHERE id = ?1")?;
                for (id, t, d) in &fixed {
                    stmt.execute(rusqlite::params![id, t, d])?;
                }
            }
            tx.commit()?;
            Ok(fixed.len())
        })
    }
}
