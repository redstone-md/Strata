//! `table`/`table2` sections: per-segment chunk offset lists.
//!
//! Payload: `u32 count` | 4 pad | `u64 base offset` | 4 pad | `u32 adler32` of bytes 0..20 |
//! `count × u32` entries | `u32 adler32` of the entries (absent in SMART images).
//! Entry: bit 31 = chunk is zlib-compressed, bits 0..31 = offset relative to `base`.
//! `table2` is an identical backup copy written right after `table`.

use super::chunk::ChunkRef;
use super::section::adler32;
use strata_kernel::bytes::{u32_le, u64_le};

const HEADER_LEN: usize = 24;
const COMPRESSED: u32 = 0x8000_0000;
const OFFSET_MASK: u32 = 0x7FFF_FFFF;

/// One parsed table section; never fails, damaged input just yields fewer entries.
pub(super) struct TableSection {
    base: u64,
    entries: Vec<u32>,
    intact: bool,
    section_start: u64,
}

impl TableSection {
    pub fn parse(data: &[u8], section_start: u64) -> Self {
        let count = u32_le(data, 0).unwrap_or(0) as usize;
        let base = u64_le(data, 8).unwrap_or(0);
        let header_ok = data.get(..20).map(adler32).is_some_and(|sum| u32_le(data, 20) == Some(sum));
        let available = data.len().saturating_sub(HEADER_LEN) / 4;
        let n = count.min(available);
        let body = data.get(HEADER_LEN..HEADER_LEN + n * 4).unwrap_or_default();
        let entries = body.chunks_exact(4).filter_map(|e| u32_le(e, 0)).collect();
        // SMART tables have no entry checksum; only verify it when it is there.
        let entries_ok = match u32_le(data, HEADER_LEN + n * 4) {
            Some(stored) => adler32(body) == stored,
            None => true,
        };
        Self { base, entries, intact: header_ok && entries_ok && n == count, section_start }
    }

    pub fn intact(&self) -> bool {
        self.intact
    }

    pub fn section_start(&self) -> u64 {
        self.section_start
    }

    pub fn last_offset(&self) -> Option<u64> {
        self.entries.last().map(|e| self.absolute(*e))
    }

    fn absolute(&self, entry: u32) -> u64 {
        self.base.saturating_add(u64::from(entry & OFFSET_MASK))
    }
}

/// A table placed in the image: which segment, which global chunk numbers, where the last
/// chunk ends (its size is not stored; it runs to the end of the data section).
pub(super) struct ChunkTable {
    segment: usize,
    first: u64,
    table: TableSection,
    tail_end: u64,
}

impl ChunkTable {
    pub fn new(segment: usize, first: u64, table: TableSection, tail_end: u64) -> Self {
        Self { segment, first, table, tail_end }
    }

    pub fn end(&self) -> u64 {
        self.first + self.table.entries.len() as u64
    }

    pub fn locate(&self, chunk: u64) -> Option<ChunkRef> {
        let j = usize::try_from(chunk.checked_sub(self.first)?).ok()?;
        let entry = *self.table.entries.get(j)?;
        let offset = self.table.absolute(entry);
        let end = self.table.entries.get(j + 1).map_or(self.tail_end, |next| self.table.absolute(*next));
        Some(ChunkRef { segment: self.segment, offset, stored: end.saturating_sub(offset), compressed: entry & COMPRESSED != 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[u32], base: u64) -> Vec<u8> {
        let mut t = (entries.len() as u32).to_le_bytes().to_vec();
        t.extend([0; 4]);
        t.extend(base.to_le_bytes());
        t.extend([0; 4]);
        t.extend(adler32(&t).to_le_bytes());
        let body: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        t.extend(&body);
        t.extend(adler32(&body).to_le_bytes());
        t
    }

    #[test]
    fn locates_chunks_and_flags() {
        let t = TableSection::parse(&table(&[0x10 | COMPRESSED, 0x30], 100), 0);
        assert!(t.intact());
        let ct = ChunkTable::new(1, 5, t, 200);
        assert_eq!(ct.locate(5), Some(ChunkRef { segment: 1, offset: 116, stored: 32, compressed: true }));
        assert_eq!(ct.locate(6), Some(ChunkRef { segment: 1, offset: 148, stored: 52, compressed: false }));
        assert_eq!(ct.locate(7), None);
        assert_eq!(ct.locate(4), None);
    }

    #[test]
    fn damage_is_detected_not_fatal() {
        let mut raw = table(&[1, 2, 3], 0);
        raw[24] ^= 0xFF;
        assert!(!TableSection::parse(&raw, 0).intact());
        raw[0] = 0xFF;
        let t = TableSection::parse(&raw, 0);
        assert!(!t.intact() && t.entries.len() <= 4);
        assert!(!TableSection::parse(&[1, 2], 0).intact());
    }
}
