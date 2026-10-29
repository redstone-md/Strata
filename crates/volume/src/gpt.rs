//! GUID partition table (primary header, falling back to the backup at the disk end).

use crate::candidate::{Evidence, VolumeCandidate};
use crate::probe::{GptHeader, SECTOR};
use crate::{BootSector, FsKind};
use strata_kernel::bytes::{u32_le, u64_le};
use strata_source::BlockSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptEntry {
    pub name: String,
    pub start: u64,
    pub len: u64,
}

pub fn read(source: &dyn BlockSource, sector: u64) -> Vec<GptEntry> {
    let backup_lba = (source.len() / sector).saturating_sub(1);
    [1, backup_lba]
        .into_iter()
        .map(|lba| read_at(source, lba * sector, sector))
        .find(|v| !v.is_empty())
        .unwrap_or_default()
}

fn read_at(source: &dyn BlockSource, header_off: u64, sector: u64) -> Vec<GptEntry> {
    let Ok(h) = source.read_vec(header_off, 92) else { return Vec::new() };
    if h.get(..8) != Some(b"EFI PART") {
        return Vec::new();
    }
    let (Some(table_lba), Some(count), Some(size)) = (u64_le(&h, 72), u32_le(&h, 80), u32_le(&h, 84)) else {
        return Vec::new();
    };
    entries(source, 0, table_lba * sector, count, size, sector)
}

/// Entries of the table at absolute `table_off`, LBAs counted from `disk_start`.
fn entries(source: &dyn BlockSource, disk_start: u64, table_off: u64, count: u32, size: u32, sector: u64) -> Vec<GptEntry> {
    let (count, size) = (count.min(1024) as usize, size as usize);
    if !(128..=4096).contains(&size) {
        return Vec::new();
    }
    let Ok(table) = source.read_vec(table_off, count * size) else { return Vec::new() };
    table
        .chunks_exact(size)
        .filter(|e| e[..16].iter().any(|b| *b != 0))
        .filter_map(|e| {
            let first = u64_le(e, 32)?;
            let last = u64_le(e, 40)?;
            let name = strata_kernel::bytes::utf16le(e.get(56..128)?);
            if last < first {
                return None;
            }
            Some(GptEntry {
                name,
                start: disk_start.checked_add(first.checked_mul(sector)?)?,
                len: (last - first + 1).checked_mul(sector)?,
            })
        })
        .collect()
}

/// Volumes listed by a GPT header found anywhere on the medium (a lost disk's own table,
/// or the backup header that survived a wipe of the primary).
pub fn candidates(source: &dyn BlockSource, header: &GptHeader) -> Vec<VolumeCandidate> {
    let table_off = header.disk_start.saturating_add(header.entries_lba.saturating_mul(SECTOR));
    let found_at = header.disk_start.saturating_add(header.my_lba.saturating_mul(SECTOR));
    entries(source, header.disk_start, table_off, header.entry_count, header.entry_size, SECTOR)
        .into_iter()
        .map(|e| {
            let fs = source.read_vec(e.start, BootSector::HEAD_LEN).ok().and_then(|h| BootSector::parse(&h)).map_or(FsKind::Unknown, |b| b.kind);
            VolumeCandidate { start: e.start, len: e.len, fs, evidence: Evidence::PartitionTable, found_at }
        })
        .collect()
}
