//! Lost and deleted partitions found by the single-pass deep scan.
//!
//! Every 512-byte-aligned sector is checked for the three signature spots volume structures
//! share (boot signature at 510, ext magic at 0x38, `EFI PART` at 0). Stepping by sector
//! touches two cache lines per 512 bytes instead of every byte, so this detector costs far
//! less than a `memmem` over the chunk would.

use crate::boot::FsKind;
use crate::candidate::VolumeCandidate;
use crate::probe::{SECTOR, Structure};
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

const SECTOR_LEN: usize = SECTOR as usize;

#[derive(Debug, Default, Clone, Copy)]
pub struct PartitionDetector;

impl PartitionDetector {
    pub const ID: &'static str = "volume.partition";

    /// Candidate volumes stored in a hit this detector emitted.
    pub fn candidates_of(hit: &Hit) -> Vec<VolumeCandidate> {
        serde_json::from_value(hit.details["candidates"].clone()).unwrap_or_default()
    }

    /// GPT header stored in a hit this detector emitted.
    pub fn gpt_of(hit: &Hit) -> Option<crate::GptHeader> {
        serde_json::from_value(hit.details.get("gpt")?.clone()).ok()
    }

    fn quick(s: &[u8]) -> bool {
        s.get(510..512) == Some(&[0x55, 0xAA]) || s.get(0x38..0x3A) == Some(&[0x53, 0xEF]) || s.get(..8) == Some(b"EFI PART")
    }

    /// FAT32/exFAT keep an identical copy `n` sectors after the first: when the copy is in
    /// the chunk, the pair tells which is which.
    fn same_boot(chunk: &[u8], pos: usize, delta: isize, base: u64, expect: &Structure) -> bool {
        let Some(other) = pos.checked_add_signed(delta) else { return false };
        matches!((Structure::at(chunk, other, base + other as u64), expect),
            (Some(Structure::Boot { boot: a, .. }), Structure::Boot { boot: b, .. }) if a == *b)
    }

    fn emit(chunk: &[u8], pos: usize, base: u64, sink: &mut dyn HitSink) {
        let at = base + pos as u64;
        let Some(structure) = Structure::at(chunk, pos, at) else { return };
        let mut candidates = structure.candidates(at);
        if let Structure::Boot { boot, backup_sector: Some(n) } = &structure
            && boot.kind != FsKind::Ntfs
        {
            let delta = (*n as usize).saturating_mul(SECTOR_LEN) as isize;
            if Self::same_boot(chunk, pos, -delta, base, &structure) {
                return; // the primary right before this copy already produced the hit
            }
            if Self::same_boot(chunk, pos, delta, base, &structure) {
                candidates.truncate(1);
            }
        }
        let gpt = match &structure {
            Structure::Gpt(h) => Some(*h),
            _ => None,
        };
        if candidates.is_empty() && gpt.is_none() {
            return;
        }
        let label = structure.describe();
        let details = serde_json::json!({ "structure": label, "candidates": candidates, "gpt": gpt });
        sink.emit(
            Hit::new(PartitionDetector::ID, HitCategory::Partition, at, SECTOR_LEN)
                .label(label.clone())
                .value(format!("{label} @{at:#x}"))
                .confidence(Confidence::MEDIUM)
                .details(details),
        );
    }
}

impl Detector for PartitionDetector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    /// An ext superblock spans 1 KiB from its sector.
    fn max_match(&self) -> usize {
        1024
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let mut pos = ((SECTOR - base % SECTOR) % SECTOR) as usize;
        while let Some(s) = chunk.get(pos..pos + SECTOR_LEN) {
            if Self::quick(s) {
                Self::emit(chunk, pos, base, sink);
            }
            pos += SECTOR_LEN;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::tests::ntfs_boot;
    use crate::candidate::Evidence;
    use crate::probe::tests::superblock;

    fn scan(data: &[u8], base: u64) -> Vec<Hit> {
        let mut hits = Vec::new();
        PartitionDetector.scan(data, base, &mut hits);
        hits
    }

    #[test]
    fn finds_aligned_structures_only() {
        let mut data = vec![0u8; 64 << 10];
        data[4096..4608].copy_from_slice(&ntfs_boot(4096));
        data[8192 + 100..8192 + 612].copy_from_slice(&ntfs_boot(4096)); // unaligned: ignored
        data[16384..17408].copy_from_slice(&superblock(256));
        let hits = scan(&data, 1 << 20);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].offset, (1 << 20) + 4096);
        let c = PartitionDetector::candidates_of(&hits[0]);
        assert_eq!((c[0].start, c[0].fs, c[0].evidence), ((1 << 20) + 4096, FsKind::Ntfs, Evidence::BootSector));
        let c = PartitionDetector::candidates_of(&hits[1]);
        assert_eq!(c[0].start, (1 << 20) + 16384 - 1024);
    }

    #[test]
    fn unaligned_chunk_base_still_checks_sector_boundaries() {
        let mut data = vec![0u8; 8192];
        data[312..824].copy_from_slice(&ntfs_boot(100)); // absolute 1024 when base = 712
        assert_eq!(scan(&data, 712).len(), 1);
    }

    #[test]
    fn noise_produces_nothing() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let data: Vec<u8> = (0..1 << 20)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            })
            .collect();
        assert!(scan(&data, 0).is_empty());
    }
}
