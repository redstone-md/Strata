//! A volume that a stray on-disk structure says should exist, and the rules that pick the
//! believable ones out of many overlapping guesses.

use crate::FsKind;
use serde::{Deserialize, Serialize};
use strata_kernel::ByteRange;

/// Which structure vouches for a candidate volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Boot sector in the volume's first sector.
    BootSector,
    /// ext superblock at volume offset 1024.
    Superblock,
    /// Entry of an MBR, EBR or GPT found away from the disk's own tables.
    PartitionTable,
    /// Backup boot sector (NTFS last sector, FAT32 sector 6, exFAT sector 12).
    BackupBootSector,
    /// ext backup superblock of a later block group.
    BackupSuperblock,
}

impl Evidence {
    /// Lower is more trustworthy: primary structures beat tables, tables beat backups.
    pub fn rank(self) -> u8 {
        match self {
            Self::BootSector | Self::Superblock => 0,
            Self::PartitionTable => 1,
            Self::BackupBootSector | Self::BackupSuperblock => 2,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::BootSector => "boot sector",
            Self::Superblock => "superblock",
            Self::PartitionTable => "partition table entry",
            Self::BackupBootSector => "backup boot sector",
            Self::BackupSuperblock => "backup superblock",
        }
    }
}

/// One guess at a lost volume: where it starts, how long it says it is, what it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeCandidate {
    pub start: u64,
    pub len: u64,
    pub fs: FsKind,
    pub evidence: Evidence,
    /// Absolute offset of the structure the guess comes from.
    pub found_at: u64,
}

impl VolumeCandidate {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.start, self.len)
    }

    /// Volume start `back` bytes before `found_at`, if that is not before the disk start.
    pub(crate) fn behind(found_at: u64, back: u64, len: u64, fs: FsKind, evidence: Evidence) -> Option<Self> {
        let start = found_at.checked_sub(back)?;
        (len > 0).then_some(Self { start, len, fs, evidence, found_at })
    }

    fn overlaps(&self, r: &ByteRange) -> bool {
        self.range().intersect(r).is_some()
    }
}

/// Picks lost volumes out of raw candidates.
///
/// Candidates from the same structure are alternative readings of it (a lone NTFS boot sector
/// is either a first sector or a backup); `score` (e.g. entries a parser recovered, `None` if
/// it parses at all) chooses between them. Winners are then accepted best evidence first,
/// never overlapping a known volume or each other.
pub struct CandidateResolver {
    known: Vec<ByteRange>,
    disk_len: u64,
}

impl CandidateResolver {
    pub fn new(known: Vec<ByteRange>, disk_len: u64) -> Self {
        Self { known, disk_len }
    }

    pub fn resolve(&self, mut candidates: Vec<VolumeCandidate>, mut score: impl FnMut(&VolumeCandidate) -> Option<usize>) -> Vec<VolumeCandidate> {
        candidates.retain(|c| c.start < self.disk_len && !self.known.iter().any(|k| c.overlaps(k)));
        for c in &mut candidates {
            c.len = c.len.min(self.disk_len - c.start);
        }
        candidates.sort_by_key(|c| (c.found_at, c.evidence.rank(), c.start));
        candidates.dedup_by_key(|c| (c.found_at, c.start, c.fs));
        let mut winners: Vec<(VolumeCandidate, usize)> = Vec::new();
        for group in candidates.chunk_by(|a, b| a.found_at == b.found_at) {
            let best = group.iter().filter_map(|c| score(c).map(|s| (*c, s))).max_by_key(|(c, s)| (*s, std::cmp::Reverse(c.evidence.rank())));
            winners.extend(best);
        }
        winners.sort_by_key(|(c, s)| (c.evidence.rank(), std::cmp::Reverse(*s), c.start));
        let mut accepted: Vec<VolumeCandidate> = Vec::new();
        for (c, _) in winners {
            if !accepted.iter().any(|a| c.overlaps(&a.range())) {
                accepted.push(c);
            }
        }
        accepted.sort_by_key(|c| c.start);
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(start: u64, len: u64, evidence: Evidence, found_at: u64) -> VolumeCandidate {
        VolumeCandidate { start, len, fs: FsKind::Ntfs, evidence, found_at }
    }

    #[test]
    fn keeps_the_reading_that_parses_and_drops_overlaps() {
        let known = vec![ByteRange::new(0, 1000)];
        let raw = vec![
            cand(500, 100, Evidence::BootSector, 500),
            // A lone backup: read as first sector it is garbage, read as backup it parses.
            cand(5000, 1000, Evidence::BootSector, 5000),
            cand(4512, 1000, Evidence::BackupBootSector, 5000),
            // The primary of the same volume also survived elsewhere.
            cand(4512, 1000, Evidence::BootSector, 4512),
            cand(20_000, 1 << 40, Evidence::BootSector, 20_000),
        ];
        let parses = |c: &VolumeCandidate| (c.start != 5000).then_some(10);
        let got = CandidateResolver::new(known, 30_000).resolve(raw, parses);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].start, got[0].evidence), (4512, Evidence::BootSector));
        assert_eq!(got[1].range(), ByteRange::new(20_000, 10_000));
    }
}
