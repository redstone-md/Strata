//! Pieces of a Bitcoin Core wallet.dat without its first page. A wallet that was deleted or
//! lost to a reinstall is often fragmented: its meta page is overwritten or far away, but
//! leaf pages with `key`, `ckey`, `mkey` and `name` records survive in free space. Such
//! pages are read through the wallet parser's salvage mode, so a fragment yields the same
//! keys, addresses and (for encrypted wallets) cracking hash as a whole file.

use super::bdb::meta_at;
use super::report::hit;
use crate::wallets::bdb::{Endian, looks_like_leaf};
use crate::wallets::bitcoin_core;
use crate::wallets::records::{RECORD_TYPES, record_prefixes};
use aho_corasick::AhoCorasick;
use std::sync::LazyLock;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, HitCategory, HitSink};

/// Pages are probed at sector boundaries (a file's clusters start on one).
const ALIGN: usize = 512;
/// The default wallet.dat page size; leaf checks look at this much.
const PAGE: usize = 4096;
/// Bytes read from a leaf page onwards: several pages of one fragment are parsed together.
const WINDOW: usize = 64 * 1024;

/// Records only a wallet has (private keys, the master key, the key pool).
static WALLET_ONLY: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let strong: Vec<Vec<u8>> =
        record_prefixes().into_iter().zip(RECORD_TYPES).filter(|(_, (_, _, strong))| *strong).map(|(p, _)| p).collect();
    AhoCorasick::new(strong).expect("static patterns")
});

#[derive(Default)]
pub struct BdbFragmentDetector;

impl BdbFragmentDetector {
    fn leaf(page: &[u8]) -> bool {
        looks_like_leaf(page, Endian::Little) || looks_like_leaf(page, Endian::Big)
    }

    /// A whole file starts within the window before `pos`: the BDB detector reports it.
    fn inside_whole_file(chunk: &[u8], pos: usize) -> bool {
        (1..=WINDOW / PAGE).filter_map(|k| pos.checked_sub(k * PAGE)).any(|p| chunk.get(p..).and_then(meta_at).is_some())
    }
}

impl Detector for BdbFragmentDetector {
    fn id(&self) -> &'static str {
        "crypto.bdb_fragment"
    }

    fn max_match(&self) -> usize {
        WINDOW
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let mut pos = (ALIGN - (base % ALIGN as u64) as usize) % ALIGN;
        while pos + PAGE <= chunk.len() {
            let page = &chunk[pos..pos + PAGE];
            if !Self::leaf(page) || !WALLET_ONLY.is_match(page) || Self::inside_whole_file(chunk, pos) {
                pos += ALIGN;
                continue;
            }
            let end = (pos + WINDOW).min(chunk.len());
            let Some(report) = bitcoin_core::salvage(&chunk[pos..end]) else {
                pos += ALIGN;
                continue;
            };
            let encrypted = report.encrypted() == Some(true);
            let value = if encrypted && report.keys().is_empty() {
                format!("encrypted: {} addresses, keys need the password", report.addresses().len())
            } else {
                format!("{} keys, {} addresses", report.keys().len(), report.addresses().len())
            };
            let confidence = if report.keys().is_empty() && !encrypted { 0.6 } else { 0.9 };
            sink.emit(
                hit(self.id(), HitCategory::Wallet, base, pos, end - pos)
                    .confidence(Confidence::new(confidence))
                    .label("wallet.dat pages without their header")
                    .value(value)
                    .details(report.to_json()),
            );
            // The window was parsed as one fragment.
            pos = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallets::bdb::fixture::BdbBuilder;
    use strata_kernel::scan::Hit;

    fn scan(data: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        BdbFragmentDetector.scan(data, 0, &mut hits);
        hits
    }

    fn wallet() -> Vec<u8> {
        let mut key = b"\x04mkey".to_vec();
        key.extend(1u32.to_le_bytes());
        let mut value = vec![48];
        value.extend([7u8; 48]);
        value.push(8);
        value.extend([9u8; 8]);
        value.extend(0u32.to_le_bytes());
        value.extend(25_000u32.to_le_bytes());
        value.push(0);
        BdbBuilder::new(4096).record(&key, &value).build()
    }

    #[test]
    fn finds_leaf_pages_whose_meta_page_is_gone() {
        let file = wallet();
        let mut disk = vec![0u8; 8192];
        // Drop the meta page: only the leaf pages remain, at a sector boundary.
        disk.extend_from_slice(&file[4096..]);
        disk.extend(vec![0u8; 8192]);
        let hits = scan(&disk);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].offset, 8192);
        assert!(hits[0].value.contains("encrypted"), "{}", hits[0].value);
        assert!(hits[0].details.to_string().contains("$bitcoin$"), "the cracking hash comes along");
    }

    #[test]
    fn whole_files_are_left_to_the_bdb_detector() {
        let mut disk = vec![0u8; 4096];
        disk.extend(wallet());
        assert!(scan(&disk).is_empty());
    }
}
