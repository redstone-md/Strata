//! Raw 64-hex-digit private keys. Hex runs of this length are mostly hashes, so a run is
//! only reported when it is a valid scalar AND its surroundings say "key": a wallet keyword
//! within the context radius, or the value standing alone on its line.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::{hit, key_details, with};
use super::text::{RunScanner, ASCII_UTF16LE, HEX};
use crate::keys::{Network, PrivateKey};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use serde_json::json;
use std::sync::LazyLock;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

/// Words right before a hex run that mark it as a hash, not a key.
const HASH_WORDS: &[&str] = &[
    "sha256", "sha-256", "sha1", "sha512", "md5", "hash", "digest", "checksum", "txid", "tx id",
    "commit", "block", "merkle", "fingerprint", "sum", "etag", "nonce", "integrity",
];
const HASH_LOOKBACK: usize = 48;

static HASH_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let utf16: Vec<Vec<u8>> =
        HASH_WORDS.iter().map(|w| w.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()).collect();
    let mut pats: Vec<Vec<u8>> = HASH_WORDS.iter().map(|w| w.as_bytes().to_vec()).collect();
    pats.extend(utf16);
    AhoCorasickBuilder::new().ascii_case_insensitive(true).build(pats).expect("static patterns")
});

pub struct HexKeyDetector {
    scanner: RunScanner,
}

impl Default for HexKeyDetector {
    fn default() -> Self {
        Self { scanner: RunScanner::new(&HEX, 64, 64) }
    }
}

impl HexKeyDetector {
    /// Reject shapes real keys never have: mixed letter case, decimal-only, low variety.
    fn plausible(text: &[u8]) -> bool {
        let upper = text.iter().any(|b| b.is_ascii_uppercase());
        let lower = text.iter().any(|b| b.is_ascii_lowercase());
        if upper && lower || !(upper || lower) {
            return false;
        }
        let mut seen = 0u32;
        for b in text {
            seen |= 1 << (b.to_ascii_lowercase() as u32 % 32);
        }
        seen.count_ones() >= 9
    }

    fn after_hash_word(chunk: &[u8], start: usize) -> bool {
        let lo = start.saturating_sub(HASH_LOOKBACK);
        chunk.get(lo..start).is_some_and(|w| HASH_AC.is_match(w))
    }

    fn confidence(ctx: &Context) -> Option<Confidence> {
        let c = match (ctx.strong(), ctx.weak(), ctx.alone_on_line()) {
            (true, _, true) => 0.75,
            (true, _, false) => 0.6,
            (false, true, true) => 0.45,
            (false, true, false) => 0.35,
            (false, false, true) => 0.25,
            _ => return None,
        };
        Some(Confidence::new(c))
    }
}

impl Detector for HexKeyDetector {
    fn id(&self) -> &'static str {
        "crypto.hex_key"
    }

    fn max_match(&self) -> usize {
        self.scanner.max_bytes()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.scanner.scan(chunk, ASCII_UTF16LE, |run| {
            if !Self::plausible(run.text) {
                return;
            }
            let Some(key) = PrivateKey::from_hex(run.text) else { return };
            let end = run.start + run.byte_len;
            let ctx = Context::around(chunk, run.start, end, CONTEXT_RADIUS, run.encoding);
            if !ctx.strong() && Self::after_hash_word(chunk, run.start) {
                return;
            }
            let Some(confidence) = Self::confidence(&ctx) else { return };
            let details = with(
                key_details(&key, Network::Mainnet, None),
                json!({ "encoding": run.encoding.name(), "context": ctx.to_json() }),
            );
            sink.emit(
                hit(self.id(), HitCategory::PrivateKey, base, run.start, run.byte_len)
                    .confidence(confidence)
                    .label("raw hex private key")
                    .value(key.to_hex())
                    .details(details),
            );
        });
    }
}
