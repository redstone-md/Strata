//! Everything learned from walking the section chains of all segments.

use super::metadata::{self, StoredHashes};
use super::section::{self, Section};
use super::segment::SegmentFile;
use super::table::{ChunkTable, TableSection};
use std::collections::BTreeMap;
use strata_kernel::bytes::{u32_le, u64_le};

/// Largest payload read for any metadata/table section.
const MAX_SECTION_READ: u64 = 64 << 20;
const MAX_CHUNK_SIZE: u64 = 64 << 20;
/// EnCase volume payload; the 94-byte SMART variant has a 32-bit sector count.
const ENCASE_VOLUME_LEN: usize = 1052;

/// Media geometry from the `volume`/`disk` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Geometry {
    pub chunk_count: u64,
    pub chunk_size: u64,
    pub bytes_per_sector: u32,
    pub sector_count: u64,
}

impl Geometry {
    /// EnCase default (64 × 512) when the volume section is lost.
    pub const FALLBACK: Self = Self { chunk_count: 0, chunk_size: 64 * 512, bytes_per_sector: 512, sector_count: 0 };

    fn parse(data: &[u8]) -> Option<Self> {
        let sectors_per_chunk = u32_le(data, 8)?;
        let bytes_per_sector = u32_le(data, 12)?;
        let sector_count =
            if data.len() >= ENCASE_VOLUME_LEN { u64_le(data, 16)? } else { u64::from(u32_le(data, 16)?) };
        let chunk_size = u64::from(sectors_per_chunk).checked_mul(u64::from(bytes_per_sector))?;
        if bytes_per_sector == 0 || chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return None;
        }
        Some(Self { chunk_count: u64::from(u32_le(data, 4)?), chunk_size, bytes_per_sector, sector_count })
    }

    /// Media size in bytes, preferring the sector count over the chunk count.
    pub fn media_len(&self, chunks_found: u64) -> u64 {
        let by_sectors = self.sector_count.saturating_mul(u64::from(self.bytes_per_sector));
        let by_chunks = self.chunk_count.max(chunks_found).saturating_mul(self.chunk_size);
        if by_sectors > 0 { by_sectors } else { by_chunks }
    }
}

pub(super) struct Layout {
    pub geometry: Option<Geometry>,
    pub tables: Vec<ChunkTable>,
    /// `(first_sector, sector_count)` from `error2`.
    pub read_errors: Vec<(u64, u64)>,
    pub metadata: BTreeMap<String, String>,
    pub hashes: StoredHashes,
    /// Tables whose checksum failed and were replaced by their `table2` copy.
    pub table_fallbacks: usize,
}

impl Layout {
    pub fn read(segments: &[SegmentFile]) -> Self {
        let mut layout = Self {
            geometry: None,
            tables: Vec::new(),
            read_errors: Vec::new(),
            metadata: BTreeMap::new(),
            hashes: StoredHashes::default(),
            table_fallbacks: 0,
        };
        let mut header = None;
        let mut header2 = None;
        let mut next_chunk = 0u64;
        for (index, segment) in segments.iter().enumerate() {
            let sections = section::walk(segment.file(), segment.len());
            let (mut primary, mut backup) = (Vec::new(), Vec::new());
            for s in &sections {
                let read = || s.read_data(segment.file(), segment.len(), MAX_SECTION_READ).unwrap_or_default();
                match s.kind() {
                    "header2" if header2.is_none() => header2 = metadata::parse_header(&read()),
                    "header" if header.is_none() => header = metadata::parse_header(&read()),
                    "volume" | "disk" if layout.geometry.is_none() => layout.geometry = Geometry::parse(&read()),
                    "table" => primary.push(TableSection::parse(&read(), s.start())),
                    "table2" => backup.push(TableSection::parse(&read(), s.start())),
                    "error2" => layout.read_errors.extend(metadata::parse_error2(&read())),
                    kind @ ("hash" | "digest") => layout.hashes.absorb(kind, &read()),
                    _ => {}
                }
            }
            for table in layout.choose_tables(primary, backup) {
                let tail = tail_end(&sections, &table, segment.len());
                let placed = ChunkTable::new(index, next_chunk, table, tail);
                next_chunk = placed.end();
                layout.tables.push(placed);
            }
        }
        layout.metadata = header2.or(header).unwrap_or_default();
        layout
    }

    /// Pair the k-th `table` with the k-th `table2`; prefer whichever copy checks out.
    fn choose_tables(&mut self, primary: Vec<TableSection>, backup: Vec<TableSection>) -> Vec<TableSection> {
        let mut backup = backup.into_iter();
        let mut chosen: Vec<TableSection> = primary
            .into_iter()
            .map(|p| match backup.next() {
                Some(b) if !p.intact() && b.intact() => {
                    self.table_fallbacks += 1;
                    b
                }
                _ => p,
            })
            .collect();
        chosen.extend(backup);
        chosen
    }

    pub fn chunks_found(&self) -> u64 {
        self.tables.last().map_or(0, ChunkTable::end)
    }
}

/// The last chunk of a table runs to the end of the section holding it (`sectors` in EnCase 6+,
/// the table itself in older images); failing that, up to the table section.
fn tail_end(sections: &[Section], table: &TableSection, file_len: u64) -> u64 {
    let Some(last) = table.last_offset() else { return 0 };
    if let Some(s) = sections.iter().find(|s| s.holds(last)) {
        return s.end().min(file_len);
    }
    if table.section_start() > last { table.section_start() } else { file_len }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_variants() {
        let mut encase = vec![0u8; ENCASE_VOLUME_LEN];
        encase[4..8].copy_from_slice(&3u32.to_le_bytes());
        encase[8..12].copy_from_slice(&64u32.to_le_bytes());
        encase[12..16].copy_from_slice(&512u32.to_le_bytes());
        encase[16..24].copy_from_slice(&(1u64 << 33).to_le_bytes());
        let g = Geometry::parse(&encase).unwrap();
        assert_eq!((g.chunk_size, g.sector_count), (32_768, 1 << 33));
        let mut smart = encase[..94].to_vec();
        smart[20] = 0xEE;
        assert_eq!(Geometry::parse(&smart).unwrap().sector_count, 0);
        assert_eq!(Geometry::parse(&smart).unwrap().media_len(0), 3 * 32_768);
        encase[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(Geometry::parse(&encase).is_none());
        assert!(Geometry::parse(&[1, 2, 3]).is_none());
    }
}
