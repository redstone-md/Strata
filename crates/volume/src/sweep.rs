//! Add-time search for volumes no partition table lists, by reading a few likely spots.
//!
//! Every probe point reads one sector before it and [`BootSector::HEAD_LEN`] from it, which
//! answers two questions with one seek: does a volume start here (boot sector or ext
//! superblock), and does one end here (NTFS backup boot sector in the last sector)?
//! The quick sweep probes every `step` (1 MiB alignment of modern tools) plus the classic
//! 63-sector start; the deep sweep adds the cylinder starts and ends of CHS-era layouts.

use crate::boot::BootSector;
use crate::candidate::{CandidateResolver, Evidence, VolumeCandidate};
use crate::probe::{SECTOR, Structure};
use strata_kernel::ByteRange;
use strata_source::BlockSource;

/// Sectors per cylinder of the 255-head, 63-sector geometry every old partitioner used.
const CYLINDER_SECTORS: u64 = 255 * 63;

pub(crate) struct Sweep {
    step: u64,
    deep: bool,
}

impl Sweep {
    pub(crate) fn new(step: u64, deep: bool) -> Self {
        Self { step, deep }
    }

    fn points(&self, len: u64) -> Vec<u64> {
        let mut points = vec![63 * SECTOR];
        if self.step > 0 {
            points.extend((1..).map(|i| i * self.step).take_while(|o| *o <= len));
        }
        if self.deep {
            let cylinder = CYLINDER_SECTORS * SECTOR;
            for c in (1..).map(|i| i * cylinder).take_while(|o| *o <= len) {
                points.extend([c, c + 63 * SECTOR]);
            }
        }
        points.sort_unstable();
        points.dedup();
        points
    }

    /// Volumes found at probe points outside `known`, best evidence first, not overlapping.
    pub(crate) fn run(&self, disk: &dyn BlockSource, known: &[ByteRange]) -> Vec<VolumeCandidate> {
        let mut candidates: Vec<VolumeCandidate> = Vec::new();
        for point in self.points(disk.len()) {
            let inside = |r: &ByteRange| r.start() < point.saturating_sub(SECTOR) && point < r.end();
            if known.iter().any(inside) || candidates.iter().any(|c| c.evidence == Evidence::BootSector && inside(&c.range())) {
                continue;
            }
            let from = point.saturating_sub(SECTOR);
            let Ok(buf) = disk.read_vec(from, (point - from) as usize + BootSector::HEAD_LEN) else { continue };
            let head = buf.get((point - from) as usize..).unwrap_or_default();
            if let Some(boot) = BootSector::parse(head) {
                candidates.push(VolumeCandidate { start: point, len: boot.declared_len, fs: boot.kind, evidence: Evidence::BootSector, found_at: point });
            }
            if point >= SECTOR
                && let Some(s @ Structure::Boot { .. }) = Structure::at(&buf, 0, from)
            {
                candidates.extend(s.candidates(from).into_iter().filter(|c| c.evidence == Evidence::BackupBootSector && c.start + c.len == point));
            }
        }
        CandidateResolver::new(known.to_vec(), disk.len()).resolve(candidates, |_| Some(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_points_cover_cylinders() {
        let quick = Sweep::new(1 << 20, false).points(20 << 20);
        let deep = Sweep::new(1 << 20, true).points(20 << 20);
        assert!(quick.contains(&(63 * 512)) && quick.contains(&(1 << 20)));
        assert!(!quick.contains(&(16065 * 512)));
        assert!(deep.contains(&(16065 * 512)) && deep.contains(&((16065 + 63) * 512)));
    }
}
