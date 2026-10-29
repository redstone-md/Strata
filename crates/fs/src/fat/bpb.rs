//! FAT BIOS parameter block: geometry and FAT width.

use strata_kernel::bytes::{u16_le, u32_le, u8_at};
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;
use strata_volume::FsKind;

/// FAT32 keeps a backup boot sector at sector 6.
const FAT32_BACKUP_SECTOR: u64 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Bpb {
    kind: FsKind,
    cluster_size: u64,
    fat_offset: u64,
    fat_bytes: u64,
    fat_count: u32,
    root_offset: u64,
    root_bytes: u64,
    root_cluster: u32,
    data_start: u64,
    cluster_count: u32,
}

impl Bpb {
    pub(super) fn parse(s: &[u8]) -> Option<Self> {
        if s.get(510..512)? != [0x55, 0xAA] {
            return None;
        }
        let bps = u64::from(u16_le(s, 11)?);
        let spc = u64::from(u8_at(s, 13)?);
        let reserved = u64::from(u16_le(s, 14)?);
        let fat_count = u32::from(u8_at(s, 16)?);
        let root_entries = u64::from(u16_le(s, 17)?);
        let total16 = u64::from(u16_le(s, 19)?);
        let fat16 = u64::from(u16_le(s, 22)?);
        let total = if total16 != 0 { total16 } else { u64::from(u32_le(s, 32)?) };
        let fat_sectors = if fat16 != 0 { fat16 } else { u64::from(u32_le(s, 36)?) };
        let sane = matches!(bps, 512 | 1024 | 2048 | 4096)
            && spc.is_power_of_two()
            && spc <= 128
            && reserved > 0
            && (1..=4).contains(&fat_count)
            && fat_sectors > 0;
        if !sane {
            return None;
        }
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let first_data = reserved + u64::from(fat_count) * fat_sectors + root_sectors;
        let clusters = total.checked_sub(first_data)? / spc;
        // FAT32 has no fixed root directory and no 16-bit FAT size; trust that over the count
        // rule so small FAT32 volumes (and slightly off counts) are read correctly.
        let fat32 = root_entries == 0 && fat16 == 0;
        let kind = match (fat32, clusters) {
            (true, _) => FsKind::Fat32,
            (false, 0..4085) => FsKind::Fat12,
            (false, _) => FsKind::Fat16,
        };
        let entry_bits: u64 = match kind {
            FsKind::Fat12 => 12,
            FsKind::Fat16 => 16,
            _ => 32,
        };
        // Clusters addressable by the FAT itself bound what the volume can use.
        let fat_bytes = fat_sectors * bps;
        let addressable = (fat_bytes * 8 / entry_bits).saturating_sub(2);
        let cluster_count = u32::try_from(clusters.min(addressable).min(0x0FFF_FFF5)).ok()?;
        Some(Self {
            kind,
            cluster_size: bps * spc,
            fat_offset: reserved * bps,
            fat_bytes,
            fat_count,
            root_offset: (reserved + u64::from(fat_count) * fat_sectors) * bps,
            root_bytes: root_sectors * bps,
            root_cluster: if fat32 { u32_le(s, 44)? } else { 0 },
            data_start: first_data * bps,
            cluster_count,
        })
    }

    /// The boot sector, falling back to the FAT32 backup copy.
    pub(super) fn locate(source: &dyn BlockSource) -> (Option<Self>, Vec<Damage>) {
        let at = |off: u64| source.read_vec(off, 512).ok().and_then(|s| Self::parse(&s)).map(|b| b.clamped(source.len()));
        if let Some(bpb) = at(0) {
            return (Some(bpb), Vec::new());
        }
        let note = Damage::corrupt(ByteRange::new(0, 512), "FAT boot sector invalid");
        for sector in [512u64, 1024, 2048, 4096] {
            if let Some(bpb) = at(FAT32_BACKUP_SECTOR * sector).filter(|b| b.kind == FsKind::Fat32) {
                return (Some(bpb), vec![note, Damage::corrupt(ByteRange::new(0, 512), "using FAT32 backup boot sector")]);
            }
        }
        (None, vec![note])
    }

    /// Never trust more clusters than the source can hold (bounds the FAT read and maps).
    fn clamped(mut self, source_len: u64) -> Self {
        let fit = source_len.saturating_sub(self.data_start).div_ceil(self.cluster_size);
        self.cluster_count = self.cluster_count.min(u32::try_from(fit).unwrap_or(u32::MAX));
        self
    }

    pub(super) fn kind(&self) -> FsKind {
        self.kind
    }

    pub(super) fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Byte offset of FAT copy `index` (0-based).
    pub(super) fn fat_offset(&self, index: u32) -> Option<u64> {
        (index < self.fat_count).then(|| self.fat_offset + u64::from(index) * self.fat_bytes)
    }

    pub(super) fn fat_bytes(&self) -> u64 {
        self.fat_bytes
    }

    /// FAT12/16 fixed root directory region; empty on FAT32.
    pub(super) fn root_region(&self) -> ByteRange {
        ByteRange::new(self.root_offset, self.root_bytes)
    }

    pub(super) fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    pub(super) fn data_start(&self) -> u64 {
        self.data_start
    }

    /// Highest valid cluster number (clusters are numbered from 2).
    pub(super) fn max_cluster(&self) -> u32 {
        self.cluster_count + 1
    }

    pub(super) fn is_cluster(&self, cluster: u32) -> bool {
        (2..=self.max_cluster()).contains(&cluster)
    }

    pub(super) fn cluster_offset(&self, cluster: u32) -> Option<u64> {
        self.is_cluster(cluster).then(|| self.data_start + u64::from(cluster - 2) * self.cluster_size)
    }
}
