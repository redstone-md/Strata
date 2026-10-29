//! Berkeley DB files (Bitcoin Core wallet.dat). A metadata page has the BDB magic at page
//! offset 12, so only 512-aligned positions are probed. Wallet record names in the following
//! 64 KiB turn a generic BDB hit into a high-confidence wallet hit.

use super::report::hit;
use crate::wallets::bdb::{Endian, MetaPage};
use crate::wallets::records::{record_prefixes, RECORD_TYPES};
use aho_corasick::AhoCorasick;
use serde_json::json;
use std::sync::LazyLock;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

const ALIGN: u64 = 512;
const RECORD_WINDOW: usize = 64 * 1024;
const META_HASH: u8 = 8;
const META_BTREE: u8 = 9;

static RECORDS: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(record_prefixes()).expect("static patterns"));

/// A metadata page as written at the start of a BDB file: the shared wallet parser's
/// validation, plus page number 0 and a matching meta page type (fewer false positives
/// when probing raw disk sectors).
pub fn meta_at(page: &[u8]) -> Option<MetaPage> {
    let meta = MetaPage::parse(page)?;
    let pgno = meta.endian.u32(page, 8)?;
    let want_type = if meta.is_btree() { META_BTREE } else { META_HASH };
    (pgno == 0 && meta.page_type == want_type).then_some(meta)
}

#[derive(Default)]
pub struct BdbDetector;

impl BdbDetector {
    /// Distinct wallet record names in `window`, with a flag for wallet-only records.
    fn wallet_records(window: &[u8]) -> (Vec<&'static str>, bool) {
        let mut seen = [false; 32];
        for m in RECORDS.find_iter(window) {
            if let Some(slot) = seen.get_mut(m.pattern().as_usize()) {
                *slot = true;
            }
        }
        let mut names = Vec::new();
        let mut strong = false;
        for (i, (name, _, is_strong)) in RECORD_TYPES.iter().enumerate() {
            if seen.get(i).copied().unwrap_or(false) {
                names.push(*name);
                strong |= *is_strong;
            }
        }
        (names, strong)
    }
}

impl Detector for BdbDetector {
    fn id(&self) -> &'static str {
        "crypto.bdb_wallet"
    }

    fn max_match(&self) -> usize {
        RECORD_WINDOW
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let first = ((ALIGN - base % ALIGN) % ALIGN) as usize;
        let mut pos = first;
        while pos + 36 <= chunk.len() {
            if let Some(meta) = chunk.get(pos..).and_then(meta_at) {
                let end = pos.saturating_add(RECORD_WINDOW).min(chunk.len());
                let (records, strong) = Self::wallet_records(&chunk[pos..end]);
                let wallet = strong && records.len() >= 2;
                let (confidence, label) = if wallet {
                    (Confidence::new(0.9), "Bitcoin Core wallet.dat (Berkeley DB)")
                } else {
                    (Confidence::new(0.2), "Berkeley DB file")
                };
                let size = u64::from(meta.last_pgno).saturating_add(1) * meta.page_size as u64;
                sink.emit(
                    hit(self.id(), HitCategory::Wallet, base, pos, meta.page_size)
                        .confidence(confidence)
                        .label(label)
                        .value(format!("bdb@{:#x}", base.saturating_add(pos as u64)))
                        .details(json!({
                            "db_type": if meta.is_btree() { "btree" } else { "hash" },
                            "big_endian": meta.endian == Endian::Big,
                            "version": meta.version,
                            "page_size": meta.page_size,
                            "last_pgno": meta.last_pgno,
                            "estimated_size": size,
                            "wallet_records": records,
                        })),
                );
            }
            pos += ALIGN as usize;
        }
    }
}

#[cfg(test)]
pub(crate) fn synthetic_meta(page_size: u32, last_pgno: u32) -> Vec<u8> {
    let mut page = vec![0u8; page_size as usize];
    page[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
    page[16..20].copy_from_slice(&9u32.to_le_bytes());
    page[20..24].copy_from_slice(&page_size.to_le_bytes());
    page[25] = META_BTREE;
    page[32..36].copy_from_slice(&last_pgno.to_le_bytes());
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_validation() {
        let page = synthetic_meta(4096, 3);
        let meta = meta_at(&page).unwrap();
        assert!(meta.is_btree() && meta.endian == Endian::Little);
        let mut bad = page.clone();
        bad[20..24].copy_from_slice(&3000u32.to_le_bytes());
        assert!(meta_at(&bad).is_none());
        assert!(meta_at(&page[..20]).is_none());
        let mut not_first = page.clone();
        not_first[8] = 1;
        assert!(meta_at(&not_first).is_none());
    }

    #[test]
    fn wallet_vs_plain_bdb() {
        let mut data = vec![0u8; 1024];
        data.extend(synthetic_meta(4096, 1));
        data.extend(b"\x04ckey\x21\x02..........\x04mkey\x01\x00\x00\x00\x04name");
        data.resize(16 * 1024, 0);
        let mut hits = Vec::new();
        BdbDetector.scan(&data, 0, &mut hits);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 1024);
        assert!(hits[0].confidence.get() > 0.8);
        let mut hits = Vec::new();
        BdbDetector.scan(&synthetic_meta(4096, 1), 512, &mut hits);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].confidence.get() < 0.5);
        let mut hits = Vec::new();
        BdbDetector.scan(&synthetic_meta(4096, 1), 100, &mut hits);
        assert!(hits.is_empty(), "unaligned page must be ignored");
    }
}
