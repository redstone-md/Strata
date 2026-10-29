//! Unit of work: everything one step stores — findings, files, events, its checkpoint — goes
//! through a [`CaseWriter`] and commits in one transaction, so a crash keeps either all of it
//! or none of it and a resumed step never duplicates or loses work.

use crate::archives::{self, ArchiveMemberRow};
use crate::case::{db, now};
use crate::timeline::{self, HostFact};
use crate::{Attribution, Case, store};
use rusqlite::{Transaction, params};
use strata_fs::FileEntry;
use strata_kernel::scan::Hit;
use strata_kernel::{EvidenceId, Result};
use strata_timeline::TimelineEvent;

/// Writes of one transaction. Obtained from [`Case::write`]; never call other `Case` methods
/// from inside the closure (the connection is held).
pub struct CaseWriter<'c> {
    tx: Transaction<'c>,
}

impl Case {
    /// Run `f` in one transaction: committed when it returns `Ok`, rolled back otherwise.
    pub fn write<T>(&self, f: impl FnOnce(&CaseWriter<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.connection();
        let w = CaseWriter { tx: conn.transaction().map_err(db)? };
        let out = f(&w)?;
        w.tx.commit().map_err(db)?;
        Ok(out)
    }
}

impl CaseWriter<'_> {
    /// Store findings; duplicates (same detector, offset and value) are ignored.
    pub fn hits(&self, id: EvidenceId, hits: &[(Hit, Attribution)]) -> Result<usize> {
        store::insert(&self.tx, id, hits).map_err(db)
    }

    /// Run trusted maintenance SQL (crate constants only) inside this transaction.
    pub(crate) fn batch(&self, sql: &str) -> Result<()> {
        self.tx.execute_batch(sql).map_err(db)
    }

    /// Count copies the repetition cap did not store (see `repeats.rs`).
    pub(crate) fn repeats(&self, id: EvidenceId, overflow: &[crate::repeats::Overflow]) -> Result<()> {
        store::add_repeats(&self.tx, id, overflow).map_err(db)
    }

    pub fn events(&self, id: EvidenceId, events: &[TimelineEvent]) -> Result<usize> {
        timeline::insert_events(&self.tx, id, events).map_err(db)
    }

    pub fn facts(&self, facts: &[HostFact]) -> Result<()> {
        timeline::insert_facts(&self.tx, facts).map_err(db)
    }

    /// Drop stored events and host facts of one evidence item (before a fresh extraction).
    pub fn clear_events(&self, id: EvidenceId) -> Result<()> {
        self.tx.execute("DELETE FROM events WHERE evidence_id = ?1", [id.get()]).map_err(db)?;
        self.tx.execute("DELETE FROM facts WHERE evidence_id = ?1", [id.get()]).map_err(db)?;
        Ok(())
    }

    /// Store the listing of one volume; rows already there are updated and keep the content
    /// types the classify step found.
    pub fn files(&self, id: EvidenceId, volume: u32, entries: &[FileEntry]) -> Result<usize> {
        let mut stmt = self
            .tx
            .prepare_cached(
                "INSERT INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state,
                 created, modified, accessed, changed) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT (evidence_id, volume_idx, file_idx) DO UPDATE SET path = excluded.path, name = excluded.name,
                 size = excluded.size, is_dir = excluded.is_dir, state = excluded.state, created = excluded.created,
                 modified = excluded.modified, accessed = excluded.accessed, changed = excluded.changed",
            )
            .map_err(db)?;
        let t = |ts: Option<strata_kernel::Timestamp>| ts.map(|t| t.unix_secs());
        for (i, e) in entries.iter().enumerate() {
            stmt.execute(params![
                id.get(), volume, i as i64, e.path, e.name, e.size as i64, e.is_dir, format!("{:?}", e.state),
                t(e.times.created), t(e.times.modified), t(e.times.accessed), t(e.times.changed)
            ])
            .map_err(db)?;
        }
        Ok(entries.len())
    }

    /// Record content-based types: `(volume, file_idx, type, mismatch, notes)`.
    pub fn file_types(&self, id: EvidenceId, rows: &[(u32, usize, String, bool, String)]) -> Result<()> {
        let mut stmt = self
            .tx
            .prepare_cached(
                "UPDATE files SET detected_type = ?4, extension_mismatch = ?5, type_notes = ?6
                 WHERE evidence_id = ?1 AND volume_idx = ?2 AND file_idx = ?3",
            )
            .map_err(db)?;
        for (vol, idx, ty, mismatch, notes) in rows {
            stmt.execute(params![id.get(), vol, *idx as i64, ty, mismatch, notes]).map_err(db)?;
        }
        Ok(())
    }

    /// Add (or replace, by member path) unpacked archive members.
    pub fn archive_members(&self, id: EvidenceId, rows: &[ArchiveMemberRow]) -> Result<usize> {
        archives::insert_members(&self.tx, id, rows).map_err(db)
    }

    pub fn clear_archive_members(&self, id: EvidenceId) -> Result<()> {
        self.tx.execute("DELETE FROM archive_members WHERE evidence_id = ?1", [id.get()]).map(|_| ()).map_err(db)
    }

    /// Result of an on-chain lookup (replaces an earlier one of the same address).
    pub fn balance(&self, b: &strata_chain::AddressBalance) -> Result<()> {
        crate::balances::insert_balance(&self.tx, b).map_err(db)
    }

    /// Results of a disk content search.
    pub fn search_results(&self, rows: &[crate::SearchResultRow]) -> Result<usize> {
        crate::search_store::insert_results(&self.tx, rows).map_err(db)
    }

    /// Resume point of the single-pass scan.
    pub fn scan_progress(&self, id: EvidenceId, len: u64, watermark: u64, completed: bool, detectors: &str) -> Result<()> {
        self.tx
            .execute(
                "INSERT OR REPLACE INTO scans (evidence_id, range_start, range_len, watermark, completed, detectors, updated_at)
                 VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6)",
                params![id.get(), len as i64, watermark as i64, completed, detectors, now()],
            )
            .map(|_| ())
            .map_err(db)
    }

    /// Where a job will resume from (JSON chosen by the step) and how far it got.
    pub fn job_checkpoint(&self, job: u32, checkpoint: &str, done: u64, total: u64) -> Result<()> {
        self.tx
            .execute(
                "UPDATE jobs SET checkpoint = ?2, done = ?3, total = ?4, updated_at = ?5 WHERE id = ?1",
                params![job, checkpoint, done as i64, total as i64, now()],
            )
            .map(|_| ())
            .map_err(db)
    }
}
