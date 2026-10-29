//! Repetition cap for low-value findings. Package lists, container layers, database dumps and
//! logs repeat the same e-mail or URL hundreds of thousands of times across thousands of files;
//! storing each copy bloats the case and buries everything else. Per value and disk:
//! - in each user file (outside system folders) the first [`RepeatCap::KEEP_PER_FILE`] copies
//!   are stored, so every user document a value occurs in stays listed;
//! - system files and free space share [`RepeatCap::KEEP_SHARED`] stored copies.
//!
//! Further copies only raise the `repeats` count of the last stored copy of their place, so
//! "seen N times" stays exact. Keys, seeds, addresses and wallets are never capped.

use crate::Attribution;
use crate::system_paths::is_system_path;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{EvidenceId, Result};

/// Copies dropped since the last commit, to add to the stored copy at `offset`.
pub struct Overflow {
    pub detector: String,
    pub value: String,
    pub offset: u64,
    pub extra: u64,
}

#[derive(Default)]
pub struct RepeatCap {
    /// Per value and place: copies seen, offset of the last stored copy.
    seen: HashMap<u64, (u32, u64)>,
}

impl RepeatCap {
    pub const KEEP_PER_FILE: u32 = 4;
    pub const KEEP_SHARED: u32 = 8;

    fn capped(category: HitCategory) -> bool {
        matches!(category, HitCategory::Identity | HitCategory::Url | HitCategory::Marker)
    }

    /// The place a copy counts against and how many copies that place keeps.
    fn key(hit: &Hit, at: &Attribution) -> (u64, u32) {
        let mut h = DefaultHasher::new();
        (&hit.detector, &hit.value).hash(&mut h);
        let keep = match &at.file {
            Some(f) if !is_system_path(&f.path) => {
                f.path.hash(&mut h);
                Self::KEEP_PER_FILE
            }
            _ => Self::KEEP_SHARED,
        };
        (h.finish(), keep)
    }

    /// Split a batch into the copies to store and the counts to add to stored ones.
    pub fn filter(&mut self, hits: Vec<(Hit, Attribution)>) -> (Vec<(Hit, Attribution)>, Vec<Overflow>) {
        let mut keep = Vec::with_capacity(hits.len());
        let mut overflow: HashMap<u64, Overflow> = HashMap::new();
        for (hit, at) in hits {
            if !Self::capped(hit.category) {
                keep.push((hit, at));
                continue;
            }
            let (key, keep_n) = Self::key(&hit, &at);
            let (seen, last) = self.seen.entry(key).or_insert((0, hit.offset));
            *seen = seen.saturating_add(1);
            if *seen <= keep_n {
                *last = hit.offset;
                keep.push((hit, at));
            } else {
                let offset = *last;
                overflow
                    .entry(key)
                    .or_insert_with(|| Overflow { detector: hit.detector.clone(), value: hit.value.clone(), offset, extra: 0 })
                    .extra += 1;
            }
        }
        (keep, overflow.into_values().collect())
    }
}

impl crate::Case {
    /// Apply the cap to findings already stored (cases scanned before it existed, or copies
    /// stored again after a resume): copies past the ones a place keeps are removed and
    /// counted on the last kept one. Returns the rows removed.
    pub fn compact_repeats(&self, id: EvidenceId) -> Result<usize> {
        let place = "CASE WHEN file_path IS NULL OR file_path IN (SELECT path FROM temp.system_files) THEN '' ELSE file_path END";
        let keep = format!("(CASE WHEN place = '' THEN {} ELSE {} END)", RepeatCap::KEEP_SHARED, RepeatCap::KEEP_PER_FILE);
        let sql = format!(
            "CREATE TEMP TABLE IF NOT EXISTS excess (id INTEGER PRIMARY KEY, keeper INTEGER NOT NULL, repeats INTEGER NOT NULL);
             DELETE FROM excess;
             INSERT INTO excess
             SELECT id, keeper, repeats FROM (
                 SELECT id, rn, keep_n, repeats, MAX(CASE WHEN rn = keep_n THEN id END) OVER (PARTITION BY detector, value, place) AS keeper
                 FROM (SELECT id, repeats, detector, value, place, {keep} AS keep_n,
                              ROW_NUMBER() OVER (PARTITION BY detector, value, place ORDER BY offset) AS rn
                       FROM (SELECT id, repeats, detector, value, offset, {place} AS place
                             FROM hits WHERE evidence_id = {id} AND category IN ('Identity', 'Url', 'Marker'))))
             WHERE rn > keep_n;
             CREATE TEMP TABLE IF NOT EXISTS folded (keeper INTEGER PRIMARY KEY, n INTEGER NOT NULL);
             DELETE FROM folded;
             INSERT INTO folded SELECT keeper, COUNT(*) + SUM(repeats) FROM excess GROUP BY keeper;
             UPDATE hits SET repeats = repeats + (SELECT n FROM folded WHERE folded.keeper = hits.id)
             WHERE id IN (SELECT keeper FROM folded);
             DELETE FROM hits WHERE id IN (SELECT id FROM excess);",
            id = id.get()
        );
        self.with_system_files(id, |conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(&sql)?;
            let removed: i64 = tx.query_row("SELECT COUNT(*) FROM temp.excess", [], |r| r.get(0))?;
            tx.execute_batch("DROP TABLE temp.excess; DROP TABLE temp.folded;")?;
            tx.commit()?;
            Ok(removed as usize)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileRef;
    use strata_fs::EntryState;

    fn email(offset: u64, path: &str) -> (Hit, Attribution) {
        let hit = Hit::new("accounts.email", HitCategory::Identity, offset, 10).value("a@b.cz");
        let file = FileRef { path: path.into(), state: EntryState::Allocated, file_offset: 0 };
        (hit, Attribution { volume: Some(0), file: Some(file) })
    }

    #[test]
    fn keeps_first_copies_per_file_and_counts_the_rest() {
        let mut cap = RepeatCap::default();
        let batch: Vec<_> = (0..40).map(|i| email(i * 100, "/var/lib/dpkg/status")).chain([email(9_000, "/home/u/mail")]).collect();
        let (keep, overflow) = cap.filter(batch);
        assert_eq!(keep.len(), RepeatCap::KEEP_SHARED as usize + 1);
        assert_eq!(overflow.len(), 1);
        assert_eq!((overflow[0].extra, overflow[0].offset), (40 - RepeatCap::KEEP_SHARED as u64, 700));
        // Next batch: still counted against the same stored copy.
        let (keep, overflow) = cap.filter(vec![email(50_000, "/var/lib/dpkg/status")]);
        assert!(keep.is_empty());
        assert_eq!((overflow[0].extra, overflow[0].offset), (1, 700));
    }

    #[test]
    fn user_files_keep_their_own_copies() {
        let mut cap = RepeatCap::default();
        let in_one: Vec<_> = (0..10).map(|i| email(i * 100, "home/u/notes.txt")).collect();
        let (keep, _) = cap.filter(in_one);
        assert_eq!(keep.len(), RepeatCap::KEEP_PER_FILE as usize);
        let across: Vec<_> = (0..10).map(|i| email(10_000 + i, &format!("home/u/doc{i}.txt"))).collect();
        assert_eq!(cap.filter(across).0.len(), 10, "every user document keeps a copy");
    }

    #[test]
    fn compacts_stored_copies_and_keeps_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("zero.img");
        std::fs::write(&img, vec![0u8; 1 << 20]).unwrap();
        let case = crate::Case::open(&dir.path().join("t.strata")).unwrap();
        let id = case.add_evidence(&img.display().to_string()).unwrap().id;
        let copies: Vec<_> = (0..40).map(|i| email(i * 100, "usr/share/doc/x/copyright")).collect();
        case.store_hits(id, &copies).unwrap();
        assert_eq!(case.compact_repeats(id).unwrap(), 40 - RepeatCap::KEEP_SHARED as usize);
        let q = crate::HitQuery { group_by_value: true, ..crate::HitQuery::default() };
        let grouped = case.hits(&q).unwrap();
        assert_eq!((grouped.len(), grouped[0].occurrences), (1, 40));
        assert_eq!(case.hit_counts(None, 0.0).unwrap()[0].1, 1);
        assert_eq!(case.compact_repeats(id).unwrap(), 0);
    }

    #[test]
    fn keys_are_never_capped() {
        let mut cap = RepeatCap::default();
        let batch: Vec<_> = (0..40)
            .map(|i| (Hit::new("crypto.wif", HitCategory::PrivateKey, i, 51).value("5K"), Attribution::default()))
            .collect();
        assert_eq!(cap.filter(batch).0.len(), 40);
    }
}
