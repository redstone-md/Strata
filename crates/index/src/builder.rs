//! Concurrent index builder fed by the scan engine as a [`ChunkObserver`].
//!
//! Each block is profiled by the worker that owns the chunk it starts in, so block records are
//! written by exactly one thread (atomics only make the shared array sound). The same chunk
//! also goes through `SignatureDetector` and a boot-sector check, which fill the side tables;
//! signature hits in blocks wholly owned by live files only set the block flag, since nothing
//! is ever carved there.

use crate::classify::Classifier;
use crate::index::DiskIndex;
use crate::record::{BlockClass, BlockRecord, BOOT, Ownership, SIGNATURE};
use crate::side::{BootRecord, EntrySource, SignatureHit};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use strata_engine::ChunkObserver;
use strata_identify::SignatureDetector;
use strata_kernel::scan::{Detector, Hit};
use strata_volume::{BootSector, FsKind};

const SECTOR: u64 = 512;
/// ext superblock offset from the volume start; its magic sits at +0x38.
const EXT_SB: u64 = 1024;
const EXT_MAGIC_AT: usize = 0x38;

pub struct IndexBuilder {
    base: Mutex<DiskIndex>,
    records: Vec<AtomicU16>,
    block_size: u64,
    disk_len: u64,
    classifier: Classifier,
    detector: SignatureDetector,
    signatures: Mutex<Vec<SignatureHit>>,
    boots: Mutex<Vec<BootRecord>>,
}

impl IndexBuilder {
    /// Continue `index` (fresh, resumed or seeded): its records, side tables and annotations
    /// are kept and refined.
    pub fn new(index: DiskIndex) -> Self {
        let records = index.records().iter().map(|r| AtomicU16::new(r.bits())).collect();
        Self {
            block_size: u64::from(index.block_size()),
            disk_len: index.disk_len(),
            records,
            base: Mutex::new(index),
            classifier: Classifier::default(),
            detector: SignatureDetector::new(),
            signatures: Mutex::new(Vec::new()),
            boots: Mutex::new(Vec::new()),
        }
    }

    /// The index as built so far; `scanned_to` is the scan watermark (every byte below it
    /// was observed).
    pub fn snapshot(&self, scanned_to: u64) -> DiskIndex {
        let mut idx = self.base.lock().clone();
        for (dst, src) in idx.records_mut().iter_mut().zip(&self.records) {
            *dst = BlockRecord::from_bits(src.load(Ordering::Relaxed));
        }
        idx.add_signatures(self.signatures.lock().iter().copied());
        idx.add_boot_records(self.boots.lock().iter().copied());
        idx.set_scanned_to(scanned_to.max(idx.scanned_to()));
        idx
    }

    fn update(&self, block: usize, f: impl Fn(BlockRecord) -> BlockRecord) -> Option<BlockRecord> {
        let slot = self.records.get(block)?;
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let next = f(BlockRecord::from_bits(current)).bits();
            match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(BlockRecord::from_bits(current)),
                Err(seen) => current = seen,
            }
        }
    }

    fn profile_blocks(&self, data: &[u8], base: u64, end: u64) {
        let mut start = base.div_ceil(self.block_size) * self.block_size;
        while start < end {
            let rel = (start - base) as usize;
            let stop = (start + self.block_size).min(self.disk_len);
            let Some(block) = data.get(rel..((stop - base) as usize).min(data.len())) else { break };
            let content = self.classifier.classify(block);
            let index = (start / self.block_size) as usize;
            self.update(index, |r| if r.class() == BlockClass::Unreadable { r } else { r.with_content_of(content) });
            start += self.block_size;
        }
    }

    fn find_signatures(&self, data: &[u8], base: u64, end: u64) {
        let mut hits: Vec<Hit> = Vec::new();
        self.detector.scan(data, base, &mut hits);
        let mut keep = Vec::new();
        for h in hits.iter().filter(|h| h.offset < end) {
            let block = (h.offset / self.block_size) as usize;
            let Some(old) = self.update(block, |r| r.with_flags(SIGNATURE)) else { continue };
            if old.ownership() != Ownership::LiveFile {
                keep.extend(SignatureHit::from_detector_hit(h));
            }
        }
        if !keep.is_empty() {
            self.signatures.lock().extend(keep);
        }
    }

    /// Boot sectors (55 AA at +510) and ext superblocks (EF53 at +0x38) at sector-aligned
    /// positions, recognised with the volume context's own parser.
    fn find_boot_records(&self, data: &[u8], base: u64, end: u64) {
        let mut found = Vec::new();
        let mut at = base.div_ceil(SECTOR) * SECTOR;
        while at < end {
            let rel = (at - base) as usize;
            let Some(sector) = data.get(rel..) else { break };
            if sector.get(510..512) == Some(&[0x55, 0xAA]) {
                let head = &sector[..sector.len().min(BootSector::HEAD_LEN)];
                if let Some(b) = BootSector::parse(head).filter(|b| b.kind != FsKind::Unknown) {
                    found.push(BootRecord { found_at: at, volume_start: at, declared_len: b.declared_len, fs: b.kind, source: EntrySource::Scan });
                }
            }
            if at >= EXT_SB
                && sector.get(EXT_MAGIC_AT..EXT_MAGIC_AT + 2) == Some(&[0x53, 0xEF])
                && let Some(b) = BootSector::ext_superblock(sector)
            {
                found.push(BootRecord { found_at: at, volume_start: at - EXT_SB, declared_len: b.declared_len, fs: b.kind, source: EntrySource::Scan });
            }
            at += SECTOR;
        }
        for r in &found {
            self.update((r.found_at / self.block_size) as usize, |rec| rec.with_flags(BOOT));
        }
        if !found.is_empty() {
            self.boots.lock().extend(found);
        }
    }
}

impl ChunkObserver for IndexBuilder {
    fn lookahead(&self) -> usize {
        (self.block_size as usize).max(self.detector.max_match()).max(BootSector::HEAD_LEN)
    }

    fn observe(&self, data: &[u8], base: u64, owned: usize) {
        let end = (base + owned as u64).min(self.disk_len);
        if base >= end {
            return;
        }
        self.profile_blocks(data, base, end);
        self.find_signatures(data, base, end);
        self.find_boot_records(data, base, end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TextKind;
    use std::sync::Arc;
    use strata_engine::{ScanControl, Scanner};
    use strata_kernel::ByteRange;
    use strata_source::{BlockSource, SourceInfo, SourceKind};

    struct Mem(Vec<u8>);
    impl BlockSource for Mem {
        fn info(&self) -> SourceInfo {
            SourceInfo { kind: SourceKind::RawImage, label: "m".into(), location: "m".into(), len: self.len(), sector_size: 512 }
        }
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> strata_kernel::Result<usize> {
            let s = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - s);
            buf[..n].copy_from_slice(&self.0[s..s + n]);
            Ok(n)
        }
        fn damage(&self) -> Vec<ByteRange> {
            Vec::new()
        }
    }

    const B: usize = 65_536;

    fn image() -> Vec<u8> {
        let mut disk = vec![0u8; 40 * B + 1000];
        for (i, b) in disk[3 * B..4 * B].iter_mut().enumerate() {
            *b = b"lorem ipsum dolor sit amet "[i % 27];
        }
        let mut x = 7u32;
        for b in &mut disk[10 * B..12 * B] {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        disk[20 * B..20 * B + 8].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        disk[20 * B + 8..20 * B + 16].copy_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        disk[30 * B + 3..30 * B + 11].copy_from_slice(b"NTFS    ");
        disk[30 * B + 11..30 * B + 13].copy_from_slice(&512u16.to_le_bytes());
        disk[30 * B + 0x28..30 * B + 0x30].copy_from_slice(&2047u64.to_le_bytes());
        disk[30 * B + 510..30 * B + 512].copy_from_slice(&[0x55, 0xAA]);
        disk
    }

    fn build(disk: Vec<u8>, workers: usize, chunk: usize) -> DiskIndex {
        let len = disk.len() as u64;
        let builder = Arc::new(IndexBuilder::new(DiskIndex::new(len, B as u32)));
        let scanner = Scanner::new(Vec::new()).with_chunk_size(chunk).with_workers(workers).with_observer(builder.clone());
        let control = ScanControl::default();
        scanner.run(&Mem(disk), ByteRange::new(0, len), &control, |_| {}).unwrap();
        builder.snapshot(control.snapshot().watermark)
    }

    #[test]
    fn profiles_every_block_and_fills_side_tables() {
        let idx = build(image(), 4, 4 * B);
        assert!(idx.is_complete());
        let r = idx.records();
        assert_eq!(r[0].class(), BlockClass::Zero);
        assert_eq!((r[3].class(), r[3].text_kind()), (BlockClass::Text, Some(TextKind::Ascii)));
        assert_eq!(r[10].class(), BlockClass::Random);
        assert_eq!(r[40].class(), BlockClass::Zero, "short last block");
        assert!(r[20].has_signature() && !r[19].has_signature());
        assert_eq!(idx.signatures().len(), 1);
        assert_eq!(idx.signatures()[0].type_id.key(), "png");
        assert!(r[30].has_boot_record());
        let boot = idx.boot_records()[0];
        assert_eq!((boot.volume_start, boot.fs, boot.declared_len), ((30 * B) as u64, FsKind::Ntfs, 2048 * 512));
        assert!(r.iter().all(|r| r.class() != BlockClass::Unscanned));
    }

    #[test]
    fn concurrency_and_chunking_do_not_change_the_result() {
        let reference = build(image(), 1, 40 * B + 1000);
        for (workers, chunk) in [(8, B), (3, 3 * B + 4096), (5, 7 * B)] {
            assert_eq!(build(image(), workers, chunk), reference, "workers {workers} chunk {chunk}");
        }
    }

    #[test]
    fn live_file_hits_only_flag_the_block_and_unreadable_blocks_stay() {
        let disk = image();
        let len = disk.len() as u64;
        let mut seed = DiskIndex::new(len, B as u32);
        seed.apply_ownership(&[(ByteRange::new(0, len), Ownership::LiveFile)]);
        seed.mark_unreadable(&[ByteRange::new(0, B as u64)]);
        let builder = Arc::new(IndexBuilder::new(seed));
        let scanner = Scanner::new(Vec::new()).with_chunk_size(4 * B).with_observer(builder.clone());
        scanner.run(&Mem(disk), ByteRange::new(0, len), &ScanControl::default(), |_| {}).unwrap();
        let idx = builder.snapshot(len);
        assert!(idx.records()[20].has_signature());
        assert!(idx.signatures().is_empty());
        assert_eq!(idx.records()[0].class(), BlockClass::Unreadable);
    }
}
