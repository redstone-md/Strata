//! Byte-level address sightings, aggregated per address: a disk can hold millions of them
//! (mail dumps, address books, spam lists), so they never go through the account resolver.
//! Rebuilt only when the findings changed.

use super::accounts::{none_if_missing, parse_disks};
use crate::Case;
use rusqlite::{Row, params};
use serde::Serialize;
use strata_accounts::{BULK_PLACE_ADDRESSES, EmailDetector};
use strata_kernel::{EvidenceId, Result};

/// Rows written per write transaction (the write lock is released in between).
const BATCH: usize = 20_000;

/// Distinct addresses per place: a file, or one MiB of free space (`@<MiB index>`), then per
/// address the totals and its least crowded place.
const AGGREGATE: &str = "
WITH m AS MATERIALIZED (
    SELECT evidence_id e, IFNULL(file_path, '@' || (offset >> 20)) place, lower(value) addr, MIN(value) v,
           COUNT(*) + SUM(repeats) c, MIN(id) id
    FROM hits NOT INDEXED WHERE detector = ?1 GROUP BY 1, 2, 3),
p AS MATERIALIZED (SELECT e, place, COUNT(*) n FROM m GROUP BY e, place)
SELECT addr, MIN(v), SUM(c), COUNT(*), GROUP_CONCAT(DISTINCT e), MIN(n), MIN(id)
FROM m JOIN p USING (e, place) GROUP BY addr";

/// How one address was sighted byte-level across the case.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Mention {
    /// Case-folded address.
    pub address: String,
    /// The address as stored in one finding (for exact finding lookups).
    pub found_as: String,
    pub hits: u64,
    /// Files (or MiB of free space) it was found in.
    pub places: u64,
    pub disks: Vec<EvidenceId>,
    /// Distinct addresses in its least crowded place.
    pub density: u64,
    /// One finding of it.
    pub sample: i64,
}

impl Mention {
    fn read(r: &Row) -> rusqlite::Result<Self> {
        let n = |i: usize| r.get::<_, i64>(i).map(|v| v.max(0) as u64);
        Ok(Self {
            address: r.get(0)?,
            found_as: r.get(1)?,
            hits: n(2)?,
            places: n(3)?,
            disks: parse_disks(&r.get::<_, String>(4)?),
            density: n(5)?,
            sample: r.get(6)?,
        })
    }

    /// Only found where many other addresses are: a dump or a list, not a contact.
    pub fn is_bulk(&self) -> bool {
        self.density >= u64::from(BULK_PLACE_ADDRESSES)
    }
}

impl Case {
    /// Re-aggregate byte-level address sightings when findings changed since the last run.
    /// Returns the number of addresses, or `None` when the table was already current.
    pub fn refresh_mentions(&self) -> Result<Option<usize>> {
        let fingerprint: String = self.with_conn(|conn| {
            conn.query_row("SELECT IFNULL(MAX(id), 0) || ':' || (SELECT COUNT(*) FROM evidence) FROM hits", [], |r| r.get(0))
        })?;
        let stored: Option<String> = self.with_conn(|conn| {
            conn.query_row("SELECT fingerprint FROM account_mentions_state", [], |r| r.get(0)).map(Some).or_else(none_if_missing)
        })?;
        if stored.as_deref() == Some(fingerprint.as_str()) {
            return Ok(None);
        }
        self.with_write(|conn| conn.execute("DELETE FROM account_mentions", []))?;
        // Read on a pooled connection and write in batches, so the write lock is never held
        // for the whole aggregation.
        let mut written = 0;
        let mut failed = None;
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(AGGREGATE)?;
            let mut rows = stmt.query([EmailDetector::ID])?;
            let mut batch = Vec::with_capacity(BATCH);
            loop {
                let row = rows.next()?;
                if let Some(r) = row {
                    batch.push(Mention::read(r)?);
                }
                if batch.len() == BATCH || (row.is_none() && !batch.is_empty()) {
                    match self.insert_mentions(&batch) {
                        Ok(()) => written += batch.len(),
                        Err(e) => {
                            failed = Some(e);
                            return Ok(());
                        }
                    }
                    batch.clear();
                }
                if row.is_none() {
                    return Ok(());
                }
            }
        })?;
        if let Some(e) = failed {
            return Err(e);
        }
        self.with_write(|conn| conn.execute("INSERT OR REPLACE INTO account_mentions_state (id, fingerprint) VALUES (1, ?1)", [&fingerprint]))?;
        Ok(Some(written))
    }

    fn insert_mentions(&self, batch: &[Mention]) -> Result<()> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO account_mentions (address, found_as, hits, places, disks, density, sample) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )?;
                for m in batch {
                    let disks: Vec<String> = m.disks.iter().map(|d| d.get().to_string()).collect();
                    stmt.execute(params![m.address, m.found_as, m.hits as i64, m.places as i64, disks.join(","), m.density as i64, m.sample])?;
                }
            }
            tx.commit()
        })
    }

    /// How an address was sighted byte-level, if at all.
    pub fn mention(&self, address: &str) -> Result<Option<Mention>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT address, found_as, hits, places, disks, density, sample FROM account_mentions WHERE address = lower(?1)",
                [address.trim()],
                Mention::read,
            )
            .map(Some)
            .or_else(none_if_missing)
        })
    }
}
