use crate::boot::{BootSector, FsKind};
use crate::{gpt, mbr};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_kernel::ByteRange;
use strata_source::{BlockSource, SliceSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeOrigin {
    Mbr,
    Gpt,
    /// Found by boot-sector sweep, not referenced by any table (deleted or lost).
    Recovered,
    /// The evidence itself is a single filesystem (volume image).
    WholeSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub index: u32,
    pub range: ByteRange,
    pub fs: FsKind,
    pub origin: VolumeOrigin,
    pub label: String,
}

impl Volume {
    pub fn open(&self, disk: Arc<dyn BlockSource>) -> Arc<dyn BlockSource> {
        Arc::new(SliceSource::new(disk, self.range, self.label.clone()))
    }
}

pub struct VolumeScanner {
    sector: u64,
    sweep_step: u64,
}

impl Default for VolumeScanner {
    fn default() -> Self {
        Self { sector: 512, sweep_step: 1 << 20 }
    }
}

impl VolumeScanner {
    /// `sweep_step`: alignment for lost-partition search (0 disables the sweep).
    pub fn new(sector: u64, sweep_step: u64) -> Self {
        Self { sector, sweep_step }
    }

    pub fn scan(&self, disk: &dyn BlockSource) -> Vec<Volume> {
        if let Some(boot) = self.boot_at(disk, 0) {
            return vec![Volume {
                index: 0,
                range: ByteRange::new(0, disk.len()),
                fs: boot.kind,
                origin: VolumeOrigin::WholeSource,
                label: "volume".into(),
            }];
        }
        let mut found = self.from_tables(disk);
        if self.sweep_step > 0 {
            self.sweep(disk, &mut found);
        }
        found.sort_by_key(|v| v.range.start());
        for (i, v) in found.iter_mut().enumerate() {
            v.index = i as u32;
            if v.label.is_empty() {
                v.label = format!("P{i} {:?}", v.fs);
            }
        }
        found
    }

    fn boot_at(&self, disk: &dyn BlockSource, off: u64) -> Option<BootSector> {
        BootSector::parse(&disk.read_vec(off, 512).ok()?)
    }

    fn from_tables(&self, disk: &dyn BlockSource) -> Vec<Volume> {
        let entries = mbr::read(disk, self.sector);
        let (ranges, origin): (Vec<(ByteRange, String)>, _) = if mbr::is_protective(&entries) {
            let gpt = gpt::read(disk, self.sector);
            (gpt.into_iter().map(|e| (ByteRange::new(e.start, e.len), e.name)).collect(), VolumeOrigin::Gpt)
        } else {
            (entries.into_iter().map(|e| (ByteRange::new(e.start, e.len), String::new())).collect(), VolumeOrigin::Mbr)
        };
        ranges
            .into_iter()
            .map(|(range, label)| {
                let fs = self.boot_at(disk, range.start()).map_or(FsKind::Unknown, |b| b.kind);
                Volume { index: 0, range, fs, origin, label }
            })
            .collect()
    }

    /// Boot sectors at aligned offsets (and the classic 63-sector offset) outside known volumes.
    /// NTFS keeps a backup boot sector in the last sector, which lets us recover a volume whose
    /// first sector is gone.
    fn sweep(&self, disk: &dyn BlockSource, found: &mut Vec<Volume>) {
        let known: Vec<ByteRange> = found.iter().map(|v| v.range).collect();
        let mut candidates = vec![63 * self.sector];
        candidates.extend((1..).map(|i| i * self.sweep_step).take_while(|o| *o < disk.len()));
        for off in candidates {
            if known.iter().chain(found.iter().map(|v| &v.range)).any(|r| r.contains(off)) {
                continue;
            }
            if let Some(b) = self.boot_at(disk, off).filter(|b| b.kind != FsKind::Unknown) {
                let len = b.declared_len.min(disk.len() - off);
                found.push(Volume {
                    index: 0,
                    range: ByteRange::new(off, len),
                    fs: b.kind,
                    origin: VolumeOrigin::Recovered,
                    label: String::new(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::tests::ntfs_boot;
    use strata_kernel::Result;
    use strata_source::{SourceInfo, SourceKind};

    struct Mem(Vec<u8>);
    impl BlockSource for Mem {
        fn info(&self) -> SourceInfo {
            SourceInfo { kind: SourceKind::RawImage, label: "mem".into(), location: "mem".into(), len: self.len(), sector_size: 512 }
        }
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let start = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - start);
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        }
        fn damage(&self) -> Vec<ByteRange> {
            Vec::new()
        }
    }

    #[test]
    fn mbr_partition_and_lost_partition() {
        let mut disk = vec![0u8; 4 << 20];
        // MBR: one NTFS partition at LBA 63, 2048 sectors.
        disk[446 + 4] = 0x07;
        disk[446 + 8..446 + 12].copy_from_slice(&63u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&2048u32.to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk[63 * 512..64 * 512].copy_from_slice(&ntfs_boot(2048));
        // A deleted NTFS volume at 2 MiB that no table mentions.
        disk[2 << 20..(2 << 20) + 512].copy_from_slice(&ntfs_boot(1024));
        let vols = VolumeScanner::default().scan(&Mem(disk));
        assert_eq!(vols.len(), 2);
        assert_eq!((vols[0].origin, vols[0].fs, vols[0].range.start()), (VolumeOrigin::Mbr, FsKind::Ntfs, 63 * 512));
        assert_eq!((vols[1].origin, vols[1].range), (VolumeOrigin::Recovered, ByteRange::new(2 << 20, 1024 * 512)));
    }
}
