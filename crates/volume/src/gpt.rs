//! GUID partition table (primary header, falling back to the backup at the disk end).

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
    let (count, size) = (count.min(1024) as usize, size as usize);
    if !(128..=4096).contains(&size) {
        return Vec::new();
    }
    let Ok(table) = source.read_vec(table_lba * sector, count * size) else { return Vec::new() };
    table
        .chunks_exact(size)
        .filter(|e| e[..16].iter().any(|b| *b != 0))
        .filter_map(|e| {
            let first = u64_le(e, 32)?;
            let last = u64_le(e, 40)?;
            let name = strata_kernel::bytes::utf16le(e.get(56..128)?);
            (last >= first).then(|| GptEntry {
                name,
                start: first * sector,
                len: (last - first + 1) * sector,
            })
        })
        .collect()
}
