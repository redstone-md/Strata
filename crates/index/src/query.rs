//! Queries and annotations over a [`DiskIndex`]: coalesced range lists, per-cell content mix
//! for the sector map, coverage statistics.

use crate::index::DiskIndex;
use crate::record::{BlockClass, BlockRecord, FINDING, Ownership, TextKind};
use serde::Serialize;
use strata_kernel::ByteRange;

/// Content mix of one sector-map cell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CellContent {
    /// Blocks per [`BlockClass`] (indexed by `BlockClass as usize`).
    pub counts: [u32; 7],
    pub signatures: u32,
    pub findings: u32,
}

impl CellContent {
    /// The most common known class; `Unscanned` only when nothing is known. Ties go to the
    /// more notable class (unreadable, then binary, random, text, fill, zero).
    pub fn dominant(&self) -> BlockClass {
        BlockClass::ALL[1..]
            .iter()
            .copied()
            .max_by_key(|c| self.counts[*c as usize])
            .filter(|c| self.counts[*c as usize] > 0)
            .unwrap_or(BlockClass::Unscanned)
    }

    pub fn total(&self) -> u32 {
        self.counts.iter().sum()
    }

    /// 0..=1 share of `class` in the cell.
    pub fn share(&self, class: BlockClass) -> f32 {
        let total = self.total();
        if total == 0 { 0.0 } else { self.counts[class as usize] as f32 / total as f32 }
    }
}

/// Coverage statistics in blocks.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct IndexStats {
    pub block_size: u32,
    pub blocks: u64,
    /// Indexed by `BlockClass as usize`.
    pub by_class: [u64; 7],
    /// Indexed by `Ownership as usize`.
    pub by_owner: [u64; 5],
    /// Text blocks by `TextKind as usize`.
    pub by_text: [u64; 4],
    pub seeded: u64,
    pub with_signature: u64,
    pub with_finding: u64,
    pub signature_hits: u64,
    pub boot_records: u64,
    pub scanned_to: u64,
    pub disk_len: u64,
}

impl IndexStats {
    pub fn bytes_of(&self, class: BlockClass) -> u64 {
        self.by_class[class as usize] * u64::from(self.block_size)
    }
}

impl DiskIndex {
    /// Coalesced byte ranges of every block matching `pred`.
    pub fn ranges_where(&self, pred: impl Fn(BlockRecord) -> bool) -> Vec<ByteRange> {
        let mut out: Vec<ByteRange> = Vec::new();
        for (i, r) in self.records().iter().enumerate() {
            if !pred(*r) {
                continue;
            }
            let block = self.block_range(i);
            match out.last_mut() {
                Some(last) if last.end() == block.start() => *last = ByteRange::from_bounds(last.start(), block.end()),
                _ => out.push(block),
            }
        }
        out
    }

    /// Blocks that may hold data: everything except zero/fill and unreadable blocks
    /// (unscanned blocks are included). Search can skip the rest.
    pub fn interesting_ranges(&self) -> Vec<ByteRange> {
        self.ranges_where(|r| r.class().has_content())
    }

    /// Free space (unallocated, deleted files, outside volumes) that is not empty.
    pub fn nonzero_free_ranges(&self) -> Vec<ByteRange> {
        self.ranges_where(|r| r.ownership().is_free() && r.class().has_content())
    }

    pub fn text_ranges(&self) -> Vec<ByteRange> {
        self.ranges_where(|r| r.class() == BlockClass::Text)
    }

    pub fn signature_ranges(&self) -> Vec<ByteRange> {
        self.ranges_where(BlockRecord::has_signature)
    }

    pub fn class_ranges(&self, class: BlockClass) -> Vec<ByteRange> {
        self.ranges_where(|r| r.class() == class)
    }

    /// Content mix of `cells` equal slices of `range` (the whole disk for the sector map).
    pub fn cells(&self, range: ByteRange, cells: usize) -> Vec<CellContent> {
        let cells = cells.max(1);
        let cell_len = range.len().div_ceil(cells as u64).max(1);
        (0..cells)
            .map(|c| {
                let start = range.start() + c as u64 * cell_len;
                let slice = ByteRange::from_bounds(start, (start + cell_len).min(range.end()));
                let mut out = CellContent::default();
                if slice.is_empty() {
                    return out;
                }
                for r in &self.records()[self.blocks_touching(slice)] {
                    out.counts[r.class() as usize] += 1;
                    out.signatures += u32::from(r.has_signature());
                    out.findings += u32::from(r.has_finding());
                }
                out
            })
            .collect()
    }

    pub fn stats(&self) -> IndexStats {
        let mut s = IndexStats {
            block_size: self.block_size(),
            blocks: self.block_count() as u64,
            signature_hits: self.signatures().len() as u64,
            boot_records: self.boot_records().len() as u64,
            scanned_to: self.scanned_to(),
            disk_len: self.disk_len(),
            ..Default::default()
        };
        for r in self.records() {
            s.by_class[r.class() as usize] += 1;
            s.by_owner[r.ownership() as usize] += 1;
            if let Some(t) = r.text_kind() {
                s.by_text[t as usize] += 1;
            }
            s.seeded += u64::from(r.is_seeded());
            s.with_signature += u64::from(r.has_signature());
            s.with_finding += u64::from(r.has_finding());
        }
        s
    }

    /// Record ownership. Spans are applied in increasing [`Ownership`] order, so where spans
    /// share a block the most interesting owner wins.
    pub fn apply_ownership(&mut self, spans: &[(ByteRange, Ownership)]) {
        let mut spans = spans.to_vec();
        spans.sort_by_key(|(_, o)| *o);
        for (range, owner) in spans {
            for i in self.blocks_touching(range) {
                let r = self.records()[i];
                if owner > r.ownership() {
                    self.records_mut()[i] = r.with_ownership(owner);
                }
            }
        }
    }

    /// Blocks entirely inside unreadable ranges become `Unreadable` (their zero-filled
    /// bytes would otherwise look empty).
    pub fn mark_unreadable(&mut self, ranges: &[ByteRange]) {
        let unreadable = BlockRecord::content(BlockClass::Unreadable, TextKind::Ascii, 0.0);
        for range in ranges {
            for i in self.blocks_within(*range) {
                let r = self.records()[i];
                self.records_mut()[i] = r.with_content_of(unreadable);
            }
        }
    }

    /// Flag the blocks holding findings (by absolute offset).
    pub fn mark_findings(&mut self, offsets: impl IntoIterator<Item = u64>) {
        for off in offsets {
            if let Some(i) = self.block_of(off) {
                let r = self.records()[i];
                self.records_mut()[i] = r.with_flags(FINDING);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u64 = 65_536;

    fn sample() -> DiskIndex {
        let mut idx = DiskIndex::new(8 * B, B as u32);
        let classes = [
            BlockClass::Zero,
            BlockClass::Text,
            BlockClass::Text,
            BlockClass::Random,
            BlockClass::Zero,
            BlockClass::Binary,
            BlockClass::Unscanned,
            BlockClass::Fill,
        ];
        for (i, c) in classes.into_iter().enumerate() {
            idx.records_mut()[i] = BlockRecord::content(c, TextKind::Ascii, 3.0);
        }
        idx
    }

    #[test]
    fn range_queries_coalesce() {
        let mut idx = sample();
        assert_eq!(idx.text_ranges(), vec![ByteRange::new(B, 2 * B)]);
        assert_eq!(idx.interesting_ranges(), vec![ByteRange::new(B, 3 * B), ByteRange::new(5 * B, 2 * B)]);
        idx.apply_ownership(&[
            (ByteRange::new(0, 8 * B), Ownership::LiveFile),
            (ByteRange::new(3 * B + 10, 3 * B), Ownership::Unallocated),
        ]);
        assert_eq!(idx.nonzero_free_ranges(), vec![ByteRange::new(3 * B, B), ByteRange::new(5 * B, 2 * B)]);
        assert_eq!(idx.records()[0].ownership(), Ownership::LiveFile);
    }

    #[test]
    fn unreadable_only_for_whole_blocks_and_findings_flag() {
        let mut idx = sample();
        idx.mark_unreadable(&[ByteRange::new(B / 2, 2 * B)]);
        assert_eq!(idx.records()[1].class(), BlockClass::Unreadable);
        assert_eq!(idx.records()[0].class(), BlockClass::Zero);
        assert_eq!(idx.records()[2].class(), BlockClass::Text);
        idx.mark_findings([5 * B + 3, 99 * B]);
        assert!(idx.records()[5].has_finding());
        assert_eq!(idx.stats().with_finding, 1);
    }

    #[test]
    fn cells_and_stats() {
        let idx = sample();
        let cells = idx.cells(ByteRange::new(0, 8 * B), 4);
        assert_eq!(cells.len(), 4);
        assert_eq!(cells[0].dominant(), BlockClass::Text);
        assert_eq!(cells[1].dominant(), BlockClass::Random, "ties go to the later (more notable) class");
        assert_eq!(cells[1].share(BlockClass::Random), 0.5);
        assert_eq!(cells[2].dominant(), BlockClass::Binary);
        assert_eq!(cells[3].dominant(), BlockClass::Fill);
        let s = idx.stats();
        assert_eq!(s.by_class[BlockClass::Zero as usize], 2);
        assert_eq!(s.bytes_of(BlockClass::Text), 2 * B);
        assert_eq!(s.by_text[TextKind::Ascii as usize], 2);
    }
}
