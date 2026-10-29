//! Repetition cap for low-value findings. Package lists, mailing-list archives and logs repeat
//! the same e-mail or URL hundreds of thousands of times; storing each copy bloats the case
//! and buries everything else. The first [`RepeatCap::KEEP`] copies per value and place are
//! stored as usual, the rest only raise the `repeats` count of the last stored copy, so
//! "seen N times" stays exact and every file the value occurs in is still listed.
//! Keys, seeds, addresses and wallets are never capped.

use crate::Attribution;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{EvidenceId, Result};

/// Unattributed copies (free space, unknown volume) are grouped per 64 MiB of the disk.
const FREE_SPACE_BUCKET_SHIFT: u32 = 26;

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
    pub const KEEP: u32 = 16;

    fn capped(category: HitCategory) -> bool {
        matches!(category, HitCategory::Identity | HitCategory::Url | HitCategory::Marker)
    }

    fn key(hit: &Hit, at: &Attribution) -> u64 {
        let mut h = DefaultHasher::new();
        (&hit.detector, &hit.value).hash(&mut h);
        match &at.file {
            Some(f) => f.path.hash(&mut h),
            None => (at.volume, hit.offset >> FREE_SPACE_BUCKET_SHIFT).hash(&mut h),
        }
        h.finish()
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
            let key = Self::key(&hit, &at);
            let (seen, last) = self.seen.entry(key).or_insert((0, hit.offset));
            *seen = seen.saturating_add(1);
            if *seen <= Self::KEEP {
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
    /// stored again after a resume): copies past the first [`RepeatCap::KEEP`] per value and
    /// place are removed and counted on the last kept one. Returns the rows removed.
    pub fn compact_repeats(&self, id: EvidenceId) -> Result<usize> {
        let keep = RepeatCap::KEEP;
        let place = format!("COALESCE(file_path, volume_idx || ':' || (offset >> {FREE_SPACE_BUCKET_SHIFT}))");
        let sql = format!(
            "CREATE TEMP TABLE IF NOT EXISTS excess (id INTEGER PRIMARY KEY, keeper INTEGER NOT NULL, repeats INTEGER NOT NULL);
             DELETE FROM excess;
             INSERT INTO excess
             SELECT id, keeper, repeats FROM (
                 SELECT id, rn, repeats, MAX(CASE WHEN rn = {keep} THEN id END) OVER (PARTITION BY detector, value, place) AS keeper
                 FROM (SELECT id, repeats, detector, value, {place} AS place,
                              ROW_NUMBER() OVER (PARTITION BY detector, value, {place} ORDER BY offset) AS rn
                       FROM hits WHERE evidence_id = {id} AND category IN ('Identity', 'Url', 'Marker')))
             WHERE rn > {keep};
             CREATE TEMP TABLE IF NOT EXISTS folded (keeper INTEGER PRIMARY KEY, n INTEGER NOT NULL);
             DELETE FROM folded;
             INSERT INTO folded SELECT keeper, COUNT(*) + SUM(repeats) FROM excess GROUP BY keeper;
             UPDATE hits SET repeats = repeats + (SELECT n FROM folded WHERE folded.keeper = hits.id)
             WHERE id IN (SELECT keeper FROM folded);
             DELETE FROM hits WHERE id IN (SELECT id FROM excess);",
            id = id.get()
        );
        self.write(|w| w.batch(&sql))?;
        self.with_write(|conn| {
            let removed: i64 = conn.query_row("SELECT COUNT(*) FROM temp.excess", [], |r| r.get(0))?;
            conn.execute_batch("DROP TABLE temp.excess; DROP TABLE temp.folded;")?;
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
        assert_eq!(keep.len(), RepeatCap::KEEP as usize + 1);
        assert_eq!(overflow.len(), 1);
        assert_eq!((overflow[0].extra, overflow[0].offset), (40 - RepeatCap::KEEP as u64, 1_500));
        // Next batch: still counted against the same stored copy.
        let (keep, overflow) = cap.filter(vec![email(50_000, "/var/lib/dpkg/status")]);
        assert!(keep.is_empty());
        assert_eq!((overflow[0].extra, overflow[0].offset), (1, 1_500));
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
        assert_eq!(case.compact_repeats(id).unwrap(), 40 - RepeatCap::KEEP as usize);
        let q = crate::HitQuery { group_by_value: true, ..crate::HitQuery::default() };
        let grouped = case.hits(&q).unwrap();
        assert_eq!((grouped.len(), grouped[0].occurrences), (1, 40));
        assert_eq!(case.hit_counts(None).unwrap()[0].1, 40);
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
