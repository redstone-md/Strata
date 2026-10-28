//! MBR and extended (EBR) partition chains.

use strata_kernel::bytes::{u32_le, u8_at};
use strata_source::BlockSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrEntry {
    pub type_id: u8,
    pub start: u64,
    pub len: u64,
}

const EXTENDED: [u8; 3] = [0x05, 0x0F, 0x85];
const GPT_PROTECTIVE: u8 = 0xEE;

pub fn is_protective(entries: &[MbrEntry]) -> bool {
    entries.iter().any(|e| e.type_id == GPT_PROTECTIVE)
}

/// Primary and logical partitions with absolute byte offsets.
pub fn read(source: &dyn BlockSource, sector: u64) -> Vec<MbrEntry> {
    let Ok(mbr) = source.read_vec(0, 512) else { return Vec::new() };
    if mbr.get(510..512) != Some(&[0x55, 0xAA]) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for e in table(&mbr, 0, sector) {
        if EXTENDED.contains(&e.type_id) {
            follow_chain(source, e.start, sector, &mut out);
        } else {
            out.push(e);
        }
    }
    out
}

fn table(sector_data: &[u8], base: u64, sector: u64) -> Vec<MbrEntry> {
    (0..4)
        .filter_map(|i| {
            let off = 446 + i * 16;
            let type_id = u8_at(sector_data, off + 4)?;
            let lba = u64::from(u32_le(sector_data, off + 8)?);
            let count = u64::from(u32_le(sector_data, off + 12)?);
            (type_id != 0 && count != 0).then_some(MbrEntry {
                type_id,
                start: base + lba * sector,
                len: count * sector,
            })
        })
        .collect()
}

fn follow_chain(source: &dyn BlockSource, ext_start: u64, sector: u64, out: &mut Vec<MbrEntry>) {
    let mut ebr = ext_start;
    // Bound the walk: damaged chains can loop.
    for _ in 0..256 {
        let Ok(data) = source.read_vec(ebr, 512) else { return };
        if data.get(510..512) != Some(&[0x55, 0xAA]) {
            return;
        }
        let entries = table(&data, 0, sector);
        let mut next = None;
        for e in entries {
            if EXTENDED.contains(&e.type_id) {
                next = Some(ext_start + e.start);
            } else {
                out.push(MbrEntry { start: ebr + e.start, ..e });
            }
        }
        match next {
            Some(n) if n > ebr => ebr = n,
            _ => return,
        }
    }
}
