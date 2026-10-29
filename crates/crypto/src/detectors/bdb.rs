//! Berkeley DB files (Bitcoin Core wallet.dat). A metadata page has the BDB magic at page
//! offset 12, so only 512-aligned positions are probed. Wallet record names in the following
//! 64 KiB turn a generic BDB hit into a high-confidence wallet hit.

use super::report::hit;
use crate::wallets::records::{record_prefixes, RECORD_TYPES};
use aho_corasick::AhoCorasick;
use serde_json::json;
use std::sync::LazyLock;
use strata_kernel::bytes;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

const ALIGN: u64 = 512;
const RECORD_WINDOW: usize = 64 * 1024;
const MAGIC_BTREE: u32 = 0x0005_3162;
const MAGIC_HASH: u32 = 0x0006_1561;
const META_HASH: u8 = 8;
const META_BTREE: u8 = 9;

static RECORDS: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(record_prefixes()).expect("static patterns"));

/// Fields of a plausible BDB metadata page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdbMeta {
    pub btree: bool,
    pub big_endian: bool,
    pub version: u32,
    pub page_size: u32,
    pub last_pgno: u32,
}

impl BdbMeta {
    /// Port of `valid_bdb_wallet_header`, extended with endianness, page type and pgno 0.
    pub fn parse(page: &[u8]) -> Option<Self> {
        let le = bytes::u32_le(page, 12)?;
        let (big_endian, magic) = match le {
            MAGIC_BTREE | MAGIC_HASH => (false, le),
            _ => (true, bytes::u32_be(page, 12)?),
        };
        let btree = match magic {
            MAGIC_BTREE => true,
            MAGIC_HASH => false,
            _ => return None,
        };
        let rd = |off| if big_endian { bytes::u32_be(page, off) } else { bytes::u32_le(page, off) };
        let pgno = rd(8)?;
        let version = rd(16)?;
        let page_size = rd(20)?;
        let page_type = bytes::u8_at(page, 25)?;
        let last_pgno = rd(32)?;
        let type_ok = page_type == if btree { META_BTREE } else { META_HASH };
        let size_ok = page_size.is_power_of_two() && (512..=65536).contains(&page_size);
        (pgno == 0 && (1..=20).contains(&version) && size_ok && type_ok)
            .then_some(Self { btree, big_endian, version, page_size, last_pgno })
    }
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
            if let Some(meta) = chunk.get(pos..).and_then(BdbMeta::parse) {
                let end = pos.saturating_add(RECORD_WINDOW).min(chunk.len());
                let (records, strong) = Self::wallet_records(&chunk[pos..end]);
                let wallet = strong && records.len() >= 2;
                let (confidence, label) = if wallet {
                    (Confidence::new(0.9), "Bitcoin Core wallet.dat (Berkeley DB)")
                } else {
                    (Confidence::new(0.2), "Berkeley DB file")
                };
                let size = u64::from(meta.last_pgno).saturating_add(1) * u64::from(meta.page_size);
                sink.emit(
                    hit(self.id(), HitCategory::Wallet, base, pos, meta.page_size as usize)
                        .confidence(confidence)
                        .label(label)
                        .value(format!("bdb@{:#x}", base.saturating_add(pos as u64)))
                        .details(json!({
                            "db_type": if meta.btree { "btree" } else { "hash" },
                            "big_endian": meta.big_endian,
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
    page[12..16].copy_from_slice(&MAGIC_BTREE.to_le_bytes());
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
        let meta = BdbMeta::parse(&page).unwrap();
        assert!(meta.btree && !meta.big_endian);
        let mut bad = page.clone();
        bad[20..24].copy_from_slice(&3000u32.to_le_bytes());
        assert!(BdbMeta::parse(&bad).is_none());
        assert!(BdbMeta::parse(&page[..20]).is_none());
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
