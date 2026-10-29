//! The disk index aggregate: block map plus side tables of one evidence item.

use crate::record::{BlockClass, BlockRecord, BOOT, Ownership, SIGNATURE};
use crate::side::{BootRecord, EntrySource, SignatureHit};
use serde::{Deserialize, Serialize};
use strata_kernel::{ByteRange, Error, Result};

/// Default block: 64 KiB, so a 320 GB disk takes about 5 M records (10 MB).
pub const DEFAULT_BLOCK_SIZE: u32 = 64 * 1024;

/// Where the index's content came from (shown to the user, kept in the file).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    /// Imported scan files, e.g. `R-Studio scan: disk.scn`.
    pub seeded_from: Vec<String>,
    /// Bytes R-Studio reported as scanned (its progress marks), when imported.
    pub external_scanned_to: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiskIndex {
    block_size: u32,
    disk_len: u64,
    records: Vec<BlockRecord>,
    /// Every block below this offset was profiled by our own pass.
    scanned_to: u64,
    signatures: Vec<SignatureHit>,
    boot_records: Vec<BootRecord>,
    provenance: Provenance,
}

impl DiskIndex {
    /// An empty (all unscanned) index. `block_size` is rounded up to a multiple of 512.
    pub fn new(disk_len: u64, block_size: u32) -> Self {
        let block_size = block_size.max(512).div_ceil(512) * 512;
        let blocks = disk_len.div_ceil(u64::from(block_size)) as usize;
        Self {
            block_size,
            disk_len,
            records: vec![BlockRecord::default(); blocks],
            scanned_to: 0,
            signatures: Vec::new(),
            boot_records: Vec::new(),
            provenance: Provenance::default(),
        }
    }

    pub(crate) fn from_parts(
        disk_len: u64,
        block_size: u32,
        records: Vec<BlockRecord>,
        scanned_to: u64,
        signatures: Vec<SignatureHit>,
        boot_records: Vec<BootRecord>,
        provenance: Provenance,
    ) -> Result<Self> {
        let expected = disk_len.div_ceil(u64::from(block_size.max(1))) as usize;
        if block_size == 0 || !block_size.is_multiple_of(512) || records.len() != expected {
            return Err(Error::format("disk index: block map does not match disk length"));
        }
        Ok(Self { block_size, disk_len, records, scanned_to: scanned_to.min(disk_len), signatures, boot_records, provenance })
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn disk_len(&self) -> u64 {
        self.disk_len
    }

    pub fn block_count(&self) -> usize {
        self.records.len()
    }

    pub fn scanned_to(&self) -> u64 {
        self.scanned_to
    }

    /// Our own pass has profiled the whole disk.
    pub fn is_complete(&self) -> bool {
        self.scanned_to >= self.disk_len
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn records(&self) -> &[BlockRecord] {
        &self.records
    }

    pub fn signatures(&self) -> &[SignatureHit] {
        &self.signatures
    }

    pub fn boot_records(&self) -> &[BootRecord] {
        &self.boot_records
    }

    /// Byte range of block `i` (the last block may be short).
    pub fn block_range(&self, i: usize) -> ByteRange {
        let start = i as u64 * u64::from(self.block_size);
        ByteRange::from_bounds(start, (start + u64::from(self.block_size)).min(self.disk_len))
    }

    pub fn block_of(&self, offset: u64) -> Option<usize> {
        (offset < self.disk_len).then(|| (offset / u64::from(self.block_size)) as usize)
    }

    pub fn record_at(&self, offset: u64) -> Option<BlockRecord> {
        self.records.get(self.block_of(offset)?).copied()
    }

    /// Blocks touched by `range` (clipped to the disk).
    pub(crate) fn blocks_touching(&self, range: ByteRange) -> std::ops::Range<usize> {
        let bs = u64::from(self.block_size);
        let start = (range.start() / bs) as usize;
        let end = (range.end().min(self.disk_len).div_ceil(bs) as usize).max(start);
        start.min(self.records.len())..end.min(self.records.len())
    }

    /// Blocks lying entirely inside `range`.
    pub(crate) fn blocks_within(&self, range: ByteRange) -> std::ops::Range<usize> {
        let bs = u64::from(self.block_size);
        let start = range.start().div_ceil(bs) as usize;
        let end_byte = range.end().min(self.disk_len);
        let end = if end_byte == self.disk_len { self.records.len() } else { (end_byte / bs) as usize };
        start.min(self.records.len())..end.max(start).min(self.records.len())
    }

    pub(crate) fn records_mut(&mut self) -> &mut [BlockRecord] {
        &mut self.records
    }

    pub(crate) fn set_scanned_to(&mut self, offset: u64) {
        self.scanned_to = offset.min(self.disk_len);
    }

    pub fn provenance_mut(&mut self) -> &mut Provenance {
        &mut self.provenance
    }

    /// Add signature hits (deduplicated by offset, type and source) and flag their blocks.
    pub fn add_signatures(&mut self, hits: impl IntoIterator<Item = SignatureHit>) {
        for h in hits {
            if let Some(b) = self.block_of(h.offset) {
                self.records[b] = self.records[b].with_flags(SIGNATURE);
                self.signatures.push(h);
            }
        }
        self.signatures.sort_by_key(|h| (h.offset, h.type_id.key(), h.source.to_bits()));
        self.signatures.dedup_by_key(|h| (h.offset, h.type_id, h.source));
    }

    /// Add boot records (deduplicated) and flag the blocks they were found in.
    pub fn add_boot_records(&mut self, records: impl IntoIterator<Item = BootRecord>) {
        for r in records {
            if let Some(b) = self.block_of(r.found_at) {
                self.records[b] = self.records[b].with_flags(BOOT);
                self.boot_records.push(r);
            }
        }
        self.boot_records.sort_by_key(|r| (r.found_at, r.volume_start, r.source.to_bits()));
        self.boot_records.dedup_by_key(|r| (r.found_at, r.volume_start, r.fs, r.source));
    }

    /// Fold `other` (same geometry) into this index. Our own content wins over seeded
    /// content, known content over unscanned; flags are combined and ownership keeps the
    /// most interesting owner.
    pub fn merge(&mut self, other: &DiskIndex) -> Result<()> {
        if other.block_size != self.block_size || other.disk_len != self.disk_len {
            return Err(Error::Other("disk index merge: different geometry".into()));
        }
        for (mine, theirs) in self.records.iter_mut().zip(&other.records) {
            *mine = merge_record(*mine, *theirs);
        }
        self.scanned_to = self.scanned_to.max(other.scanned_to);
        self.add_signatures(other.signatures.iter().copied());
        self.add_boot_records(other.boot_records.iter().copied());
        for s in &other.provenance.seeded_from {
            if !self.provenance.seeded_from.contains(s) {
                self.provenance.seeded_from.push(s.clone());
            }
        }
        self.provenance.external_scanned_to = self.provenance.external_scanned_to.max(other.provenance.external_scanned_to);
        Ok(())
    }

    /// Signature hits from `source` whose offset lies in one of `ranges` (sorted, any order
    /// in, offset order out).
    pub fn signatures_in(&self, ranges: &[ByteRange], source: EntrySource) -> Vec<&SignatureHit> {
        let ranges = ByteRange::coalesce(ranges.to_vec());
        self.signatures
            .iter()
            .filter(|h| h.source == source)
            .filter(|h| {
                let i = ranges.partition_point(|r| r.end() <= h.offset);
                ranges.get(i).is_some_and(|r| r.contains(h.offset))
            })
            .collect()
    }
}

fn rank(r: BlockRecord) -> u8 {
    match (r.class(), r.is_seeded()) {
        (BlockClass::Unscanned, _) => 0,
        (_, true) => 1,
        (_, false) => 2,
    }
}

fn merge_record(mine: BlockRecord, theirs: BlockRecord) -> BlockRecord {
    let base = if rank(theirs) > rank(mine) { mine.with_content_of(theirs) } else { mine };
    let owner = mine.ownership().max(theirs.ownership());
    let flags = theirs.bits() & (crate::record::SIGNATURE | crate::record::FINDING | BOOT);
    base.with_flags(flags).with_ownership(if owner == Ownership::Unknown { base.ownership() } else { owner })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TextKind;

    fn content(class: BlockClass) -> BlockRecord {
        BlockRecord::content(class, TextKind::Ascii, 1.0)
    }

    #[test]
    fn geometry_and_lookups() {
        let idx = DiskIndex::new(200_000, 65_536);
        assert_eq!(idx.block_count(), 4);
        assert_eq!(idx.block_range(3), ByteRange::from_bounds(196_608, 200_000));
        assert_eq!(idx.block_of(65_536), Some(1));
        assert_eq!(idx.block_of(200_000), None);
        assert_eq!(idx.blocks_touching(ByteRange::new(65_535, 2)), 0..2);
        assert_eq!(idx.blocks_within(ByteRange::new(1, 140_000)), 1..2);
        assert_eq!(idx.blocks_within(ByteRange::new(131_072, 68_928)), 2..4);
        assert_eq!(DiskIndex::new(10, 1000).block_size(), 1024);
    }

    #[test]
    fn merge_prefers_own_content_and_combines_annotations() {
        let mut a = DiskIndex::new(4 * 65_536, 65_536);
        let mut b = a.clone();
        a.records_mut()[0] = content(BlockClass::Text).seeded();
        b.records_mut()[0] = content(BlockClass::Binary).with_ownership(Ownership::Unallocated);
        a.records_mut()[1] = content(BlockClass::Zero).with_ownership(Ownership::LiveFile);
        b.records_mut()[1] = content(BlockClass::Text).seeded().with_flags(SIGNATURE);
        b.records_mut()[2] = content(BlockClass::Random);
        b.set_scanned_to(3 * 65_536);
        a.merge(&b).unwrap();
        let r = a.records();
        assert_eq!((r[0].class(), r[0].is_seeded(), r[0].ownership()), (BlockClass::Binary, false, Ownership::Unallocated));
        assert_eq!((r[1].class(), r[1].has_signature(), r[1].ownership()), (BlockClass::Zero, true, Ownership::LiveFile));
        assert_eq!(r[2].class(), BlockClass::Random);
        assert_eq!(r[3].class(), BlockClass::Unscanned);
        assert_eq!(a.scanned_to(), 3 * 65_536);
        assert!(a.merge(&DiskIndex::new(1, 65_536)).is_err());
    }
}
