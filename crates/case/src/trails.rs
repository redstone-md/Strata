//! What the wallet-trail builder reads: artefact events that name files or wallet software,
//! wallet-named and wallet-typed file entries (live, deleted, orphaned) plus the files
//! findings sit in, wallet and key findings, wallet-named archive members and mail
//! attachments. Names are prefiltered in SQL with the shared wallet-name table and judged
//! exactly by the builder. On a case with millions of rows the reads take a few seconds.

use crate::Case;
use crate::system_paths::is_system_path;
use rusqlite::Connection;
use std::collections::HashSet;
use strata_chain::addresses_in;
use strata_crypto::WalletFileName;
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_leads::EventRecord;
use strata_trails::{ArchiveMember, EntryState, FileRecord, MailAttachment, TrailInputs, WalletHit};

/// Event kinds that name a file or wallet software, read through the `events_kind` index.
const NAMING_KINDS: &str = "'DocumentOpened','FileDeleted','Download','ProgramRun','ProgramInstalled','WalletActivity'";
/// File times from artefacts (LNK target times); read by title, since the file table's own
/// walk writes millions of these.
const TIME_KINDS: &str = "'FileCreated','FileModified','FileAccessed'";
const NOT_FILESYSTEM: &str = "artifact <> 'fs' AND artifact NOT LIKE 'fs.%'";
/// Findings considered: every wallet, and keys and seeds the detectors are sure of.
const HIT_CONDITION: &str =
    "evidence_id IN (SELECT id FROM evidence) AND (category = 'Wallet' OR (category IN ('PrivateKey','ExtendedKey','Mnemonic') AND confidence >= 0.6))";
const MAX_EVENTS: usize = 200_000;
const MAX_HITS: usize = 50_000;
const MAX_ROWS: usize = 100_000;

/// `(column LIKE '%t1%' OR …)` over the shared wallet-name terms (constants, not user input).
fn like_any(column: &str, terms: impl IntoIterator<Item = String>) -> String {
    let parts: Vec<String> = terms.into_iter().map(|t| format!("{column} LIKE '%{}%'", t.replace('\'', "''"))).collect();
    format!("({})", parts.join(" OR "))
}

fn secs(v: Option<i64>) -> Option<Timestamp> {
    v.and_then(Timestamp::from_unix_secs)
}

impl Case {
    /// Everything the wallet-trail builder links, across every disk of the case.
    /// The five reads scan different tables; they run side by side on pooled read connections.
    pub fn trail_inputs(&self) -> Result<TrailInputs> {
        fn join<T>(h: std::thread::ScopedJoinHandle<'_, Result<T>>) -> Result<T> {
            h.join().unwrap_or_else(|_| Err(strata_kernel::Error::Other("a wallet-trail read stopped".into())))
        }
        std::thread::scope(|s| {
            let events = s.spawn(|| self.with_conn(trail_events));
            let files = s.spawn(|| self.with_conn(trail_files));
            let members = s.spawn(|| self.with_conn(trail_members));
            let attachments = s.spawn(|| self.with_conn(trail_attachments));
            let hits = self.with_conn(trail_hits)?;
            Ok(TrailInputs { events: join(events)?, files: join(files)?, hits, members: join(members)?, attachments: join(attachments)? })
        })
    }
}

fn trail_events(conn: &Connection) -> rusqlite::Result<Vec<EventRecord>> {
    let titles = like_any("title", WalletFileName::name_terms());
    let sql = format!(
        "SELECT id, evidence_id, data FROM events INDEXED BY events_kind
         WHERE evidence_id IN (SELECT id FROM evidence) AND kind IN ({NAMING_KINDS}) AND {NOT_FILESYSTEM}
         UNION ALL
         SELECT id, evidence_id, data FROM events WHERE kind IN ({TIME_KINDS}) AND {NOT_FILESYSTEM} AND {titles}
         LIMIT {MAX_EVENTS}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?)))?;
    let mut out: Vec<EventRecord> = rows
        .filter_map(|r| r.ok())
        .filter_map(|(id, ev, data)| Some(EventRecord { id, evidence: EvidenceId::new(ev), event: serde_json::from_str(&data).ok()? }))
        .collect();
    out.sort_by_key(|e| (e.event.at(), e.id));
    Ok(out)
}

const FILE_COLUMNS: &str = "evidence_id, volume_idx, file_idx, path, size, state, created, modified, changed, sha256, detected_type";

fn file_rows(conn: &Connection, sql: &str, seen: &mut HashSet<(u32, u32, i64)>, out: &mut Vec<FileRecord>) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let id = (r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, i64>(2)?);
        if !seen.insert(id) {
            continue;
        }
        out.push(FileRecord {
            evidence: EvidenceId::new(id.0),
            volume: id.1,
            path: r.get(3)?,
            size: r.get::<_, i64>(4)?.max(0) as u64,
            state: EntryState::from_stored(&r.get::<_, String>(5)?),
            created: secs(r.get(6)?),
            modified: secs(r.get(7)?),
            changed: secs(r.get(8)?),
            sha256: r.get(9)?,
            detected_type: r.get(10)?,
        });
    }
    Ok(())
}

/// Wallet-named and wallet-typed user files, and the files findings sit in.
fn trail_files(conn: &Connection) -> rusqlite::Result<Vec<FileRecord>> {
    let names = like_any("name", WalletFileName::name_terms());
    let folders = like_any("lower(path)", WalletFileName::folder_terms().map(str::to_string));
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    file_rows(
        conn,
        &format!("SELECT {FILE_COLUMNS} FROM files WHERE is_dir = 0 AND ({names} OR {folders} OR detected_type LIKE '%wallet%') LIMIT {MAX_ROWS}"),
        &mut seen,
        &mut out,
    )?;
    let wallet_typed = |f: &FileRecord| f.detected_type.as_deref().is_some_and(|t| t.to_lowercase().contains("wallet"));
    out.retain(|f| wallet_typed(f) || !is_system_path(&f.path) && WalletFileName::classify(&f.path).is_some());
    file_rows(
        conn,
        &format!(
            "SELECT {FILE_COLUMNS} FROM files INDEXED BY files_path
             WHERE path IN (SELECT DISTINCT file_path FROM hits WHERE {HIT_CONDITION} AND file_path IS NOT NULL) LIMIT {MAX_ROWS}"
        ),
        &mut seen,
        &mut out,
    )?;
    Ok(out)
}

fn trail_hits(conn: &Connection) -> rusqlite::Result<Vec<WalletHit>> {
    let sql = format!(
        "SELECT id, evidence_id, category, detector, label, value, offset, len, volume_idx, file_path, file_state, confidence, details
         FROM hits WHERE {HIT_CONDITION} ORDER BY id LIMIT {MAX_HITS}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let category = crate::store::category_from(&r.get::<_, String>(2)?);
        let detector: String = r.get(3)?;
        let details: serde_json::Value = serde_json::from_str(&r.get::<_, String>(12)?).unwrap_or_default();
        let mut addresses = Vec::new();
        addresses_in(&details, &mut addresses);
        addresses.sort();
        addresses.dedup();
        let records = details.get("wallet_records").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty())
            || details.get("key_count").and_then(|v| v.as_u64()).is_some_and(|n| n > 0);
        let len = r.get::<_, i64>(7)?.max(0) as u64;
        out.push(WalletHit {
            id: r.get(0)?,
            evidence: EvidenceId::new(r.get(1)?),
            has_records: records || detector.starts_with("wallet.") || category != strata_kernel::scan::HitCategory::Wallet,
            category,
            detector,
            label: r.get(4)?,
            value: r.get(5)?,
            offset: r.get::<_, i64>(6)?.max(0) as u64,
            volume: r.get(8)?,
            file_path: r.get(9)?,
            file_state: r.get::<_, Option<String>>(10)?.map(|s| EntryState::from_stored(&s)),
            confidence: r.get(11)?,
            fingerprint: details.pointer("/crack_hash/hash").and_then(|v| v.as_str()).map(str::to_string),
            size: details.get("estimated_size").and_then(|v| v.as_u64()).or(Some(len)).filter(|s| *s > 0),
            addresses,
        });
    }
    Ok(out)
}

fn trail_members(conn: &Connection) -> rusqlite::Result<Vec<ArchiveMember>> {
    let names = like_any("member_path", WalletFileName::name_terms());
    let sql = format!("SELECT evidence_id, archive_path, member_path, size, modified, encrypted FROM archive_members WHERE {names} LIMIT {MAX_ROWS}");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        Ok(ArchiveMember {
            evidence: EvidenceId::new(r.get(0)?),
            archive_path: r.get(1)?,
            member_path: r.get(2)?,
            size: r.get::<_, Option<i64>>(3)?.map(|s| s.max(0) as u64),
            modified: secs(r.get(4)?),
            encrypted: r.get(5)?,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).filter(|m| WalletFileName::classify(m.member_path.rsplit("!/").next().unwrap_or(&m.member_path)).is_some()).collect())
}

fn trail_attachments(conn: &Connection) -> rusqlite::Result<Vec<MailAttachment>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT id, evidence_id, at, subject, sender, json_extract(data, '$.attachments') FROM messages WHERE attachments > 0 LIMIT {MAX_ROWS}"
    ))?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let list: serde_json::Value = r.get::<_, Option<String>>(5)?.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        for a in list.as_array().into_iter().flatten() {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            if name.is_empty() || WalletFileName::classify(name).is_none() {
                continue;
            }
            out.push(MailAttachment {
                message: r.get(0)?,
                evidence: EvidenceId::new(r.get(1)?),
                name: name.to_string(),
                size: a.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                at: secs(r.get(2)?),
                subject: r.get(3)?,
                sender: r.get(4)?,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
