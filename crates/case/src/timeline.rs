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
    pub key: String,
    pub value: String,
    pub artifact: String,
    pub source: String,
}

impl Case {
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
                "SELECT evidence_id, key, value, artifact, source FROM facts WHERE (?1 IS NULL OR evidence_id = ?1) ORDER BY key",
            )?;
            let rows = stmt.query_map([evidence.map(|e| e.get())], |r| {
                Ok(HostFact {
                    evidence: EvidenceId::new(r.get(0)?),
                    key: r.get(1)?,
                    value: r.get(2)?,
                    artifact: r.get(3)?,
                    source: r.get(4)?,
                })
            })?;
            rows.collect()
        })
    }
}

pub(crate) fn insert_events(conn: &Connection, id: EvidenceId, events: &[TimelineEvent]) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO events (evidence_id, at, kind, title, artifact, path, deleted, crypto, data)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        ])?;
    }
    Ok(events.len())
}

pub(crate) fn insert_facts(conn: &Connection, facts: &[HostFact]) -> rusqlite::Result<()> {
    let mut stmt =
        conn.prepare_cached("INSERT INTO facts (evidence_id, key, value, artifact, source) VALUES (?1, ?2, ?3, ?4, ?5)")?;
    for f in facts {
        stmt.execute(params![f.evidence.get(), f.key, f.value, f.artifact, f.source])?;
    }
    Ok(())
}
