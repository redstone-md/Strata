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

/// Published constants that are valid scalars but never anyone's key: curve parameters
/// shipped in every crypto library and well-known hashes (lower case).
const KNOWN_CONSTANTS: &[&str] = &[
    // secp256k1 generator x / y, group order
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    // NIST P-256 generator x / y, b, order
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    // brainpoolP256r1 generator x / y
    "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
    "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
    // Ed25519 / Curve25519 base point y, order
    "6666666666666666666666666666666666666666666666666666666666666658",
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    // SHA-256 of the empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
];

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
    /// Reject published constants and shapes real keys never have: mixed letter case,
    /// decimal-only, low variety.
    fn plausible(text: &[u8]) -> bool {
        if KNOWN_CONSTANTS.iter().any(|c| c.as_bytes().eq_ignore_ascii_case(text)) {
            return false;
        }
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

#[cfg(test)]
mod constant_tests {
    use super::*;

    #[test]
    fn curve_constants_are_not_keys() {
        assert!(!HexKeyDetector::plausible(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
        assert!(!HexKeyDetector::plausible(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
        assert!(HexKeyDetector::plausible(b"0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"));
    }
}
