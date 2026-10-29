//! Raw 64-hex-digit private keys. Hex runs of this length are mostly hashes, so a run is
//! only reported when it is a valid scalar AND its surroundings say "key": a wallet keyword
//! labelling it, a strong wallet word within the context radius, or the value standing alone
//! on its line.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::{hit, key_details, with};
use super::text::{Encoding, RunScanner, ASCII_UTF16LE, HEX};
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
/// A hash word this close before the run labels it outright (`SHA256: `, `sha256:`,
/// `"digest": "`), even when wallet words are nearby (apt lists describe wallet packages).
const HASH_LABEL_LOOKBACK: usize = 16;
/// Bytes around a run within which a word labels it (`key: `, `"seed":"`). Common words
/// further away (`key`, `secret`, `seed` anywhere in a page) say nothing about the run.
const LABEL_RADIUS: usize = 40;
/// Leading or trailing zero digits a random 256-bit key practically never has (2^-32): such
/// values are counters, padded fields and table entries.
const ZERO_RUN: usize = 8;
/// Confidence of a run inside a block of hex lines (fonts, dumps, certificates) with no
/// wallet word near it: kept, but below the default noise threshold.
const HEX_BLOCK_CONFIDENCE: f32 = 0.15;
/// How far to look for the neighbouring lines.
const LINE_LOOKAROUND: usize = 512;
/// Bytes before a run searched for the JSON field it is the value of.
const JSON_LOOKBACK: usize = 64;
/// JSON field names that may hold a private key.
const KEY_FIELDS: &[&str] = &["priv", "secret", "key", "seed", "wif", "hex", "mnemonic"];
/// Bytes on each side checked for a binary surrounding.
const BINARY_LOOKAROUND: usize = 64;
/// Share of non-text bytes around a run that marks it as a string constant inside a binary
/// (a library, an executable, its deleted copy in free space) rather than written text.
const BINARY_SHARE: f32 = 0.25;

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
        let leading = text.iter().take_while(|b| **b == b'0').count();
        let trailing = text.iter().rev().take_while(|b| **b == b'0').count();
        if leading >= ZERO_RUN || trailing >= ZERO_RUN {
            return false;
        }
        let mut seen = 0u32;
        for b in text {
            seen |= 1 << (b.to_ascii_lowercase() as u32 % 32);
        }
        seen.count_ones() >= 9
    }

    fn after_hash_word(chunk: &[u8], start: usize, lookback: usize) -> bool {
        let lo = start.saturating_sub(lookback);
        chunk.get(lo..start).is_some_and(|w| HASH_AC.is_match(w))
    }

    /// The run sits inside binary data: a C string constant in a library or executable (test
    /// vectors and curve parameters in crypto libraries), not something a person wrote down.
    fn in_binary(chunk: &[u8], start: usize, end: usize) -> bool {
        let before = &chunk[start.saturating_sub(BINARY_LOOKAROUND)..start];
        let after = &chunk[end..(end + BINARY_LOOKAROUND).min(chunk.len())];
        let total = before.len() + after.len();
        if total == 0 {
            return false;
        }
        let binary = before.iter().chain(after).filter(|b| !(b.is_ascii_graphic() || b.is_ascii_whitespace())).count();
        binary as f32 / total as f32 > BINARY_SHARE
    }

    /// The run is the value of a JSON field whose name says nothing about keys (`"id": "..."`,
    /// `"hash":"..."`): identifiers and digests in configs, caches and package metadata.
    fn json_value_of_other_field(chunk: &[u8], start: usize) -> bool {
        let before = &chunk[start.saturating_sub(JSON_LOOKBACK)..start];
        let Some(rest) = before.strip_suffix(b"\"") else { return false };
        let rest = rest.trim_ascii_end();
        let Some(rest) = rest.strip_suffix(b":") else { return false };
        let Some(rest) = rest.trim_ascii_end().strip_suffix(b"\"") else { return false };
        let name_start = rest.iter().rposition(|b| *b == b'"').map_or(0, |p| p + 1);
        let name = String::from_utf8_lossy(&rest[name_start..]).to_ascii_lowercase();
        !name.is_empty() && !KEY_FIELDS.iter().any(|k| name.contains(k))
    }

    /// The line before or after is hex too: the run is one row of a hex block.
    fn in_hex_block(chunk: &[u8], start: usize, end: usize) -> bool {
        fn hex_row(line: &[u8]) -> bool {
            let t = line.trim_ascii();
            t.len() >= 32 && t.iter().all(|b| b.is_ascii_hexdigit() || *b == b' ')
        }
        let before = &chunk[start.saturating_sub(LINE_LOOKAROUND)..start];
        let prev = before.iter().rposition(|b| *b == b'\n').map(|nl| {
            let from = before[..nl].iter().rposition(|b| *b == b'\n').map_or(0, |p| p + 1);
            &before[from..nl]
        });
        let after = &chunk[end..(end + LINE_LOOKAROUND).min(chunk.len())];
        let next = after.iter().position(|b| *b == b'\n').map(|nl| {
            let rest = &after[nl + 1..];
            &rest[..rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len())]
        });
        prev.is_some_and(hex_row) || next.is_some_and(hex_row)
    }

    /// `ctx` covers the context radius, `label` only the few bytes next to the run: a strong
    /// word far away counts like a weak label, a weak word far away not at all.
    fn confidence(ctx: &Context, label: &Context) -> Option<Confidence> {
        let c = match (label.strong(), ctx.strong() || label.weak(), ctx.alone_on_line()) {
            (true, _, true) => 0.75,
            (true, _, false) => 0.6,
            (false, true, true) => 0.45,
            (false, true, false) => 0.35,
            // A bare hex line with no word about wallets is nearly always a hash; files named
            // like a key backup are raised again by triage.
            (false, false, true) => HEX_BLOCK_CONFIDENCE,
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
            if Self::after_hash_word(chunk, run.start, HASH_LABEL_LOOKBACK)
                || !ctx.strong() && Self::after_hash_word(chunk, run.start, HASH_LOOKBACK)
            {
                return;
            }
            let label = Context::around(chunk, run.start, end, LABEL_RADIUS, run.encoding);
            let Some(mut confidence) = Self::confidence(&ctx, &label) else { return };
            let ascii = matches!(run.encoding, Encoding::Ascii);
            let noise = Self::in_hex_block(chunk, run.start, end)
                || ascii && (Self::in_binary(chunk, run.start, end) || Self::json_value_of_other_field(chunk, run.start));
            if !label.strong() && noise {
                confidence = Confidence::new(HEX_BLOCK_CONFIDENCE);
            }
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

#[cfg(test)]
mod context_tests {
    use super::*;
    use strata_kernel::scan::Hit;

    const KEY: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

    fn scan(text: &str) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        HexKeyDetector::default().scan(text.as_bytes(), 0, &mut hits);
        hits
    }

    #[test]
    fn hash_labels_win_over_wallet_words() {
        let apt = format!("Package: electrum\nDescription: Bitcoin wallet\nSHA256: {KEY}\n");
        assert!(scan(&apt).is_empty());
        assert!(scan(&format!("\"digest\": \"sha256:{KEY}\"")).is_empty());
    }

    #[test]
    fn rows_of_a_hex_block_are_noise() {
        let row = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let hits = scan(&format!("{row}\n{KEY}\n{row}\n"));
        assert!(hits.iter().all(|h| h.confidence.get() <= HEX_BLOCK_CONFIDENCE + f32::EPSILON), "{hits:?}");
        let labelled = scan(&format!("my wallet private key\n{KEY}\nend\n"));
        assert_eq!(labelled.len(), 1);
        assert!(labelled[0].confidence.get() > HEX_BLOCK_CONFIDENCE, "a wallet word lifts a run out of a block");
    }
}

#[cfg(test)]
mod binary_tests {
    use super::*;
    use strata_kernel::scan::Hit;

    const KEY: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

    #[test]
    fn string_constants_in_binaries_are_noise() {
        let mut lib = vec![0x7fu8, b'E', b'L', b'F'];
        lib.extend((0..64u8).map(|i| i.wrapping_mul(37)));
        lib.extend(b"\0gcry_pk_testkey secret key\0");
        lib.extend(KEY.as_bytes());
        lib.push(0);
        lib.extend((0..64u8).map(|i| i.wrapping_mul(91) | 0x80));
        let mut hits: Vec<Hit> = Vec::new();
        HexKeyDetector::default().scan(&lib, 0, &mut hits);
        assert_eq!(hits.len(), 1, "a wallet word nearby still reports it");
        assert!(hits[0].confidence.get() <= HEX_BLOCK_CONFIDENCE + f32::EPSILON, "{hits:?}");
    }
}

#[cfg(test)]
mod json_tests {
    use super::*;
    use strata_kernel::scan::Hit;

    const KEY: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

    fn confidence(text: &str) -> Option<f32> {
        let mut hits: Vec<Hit> = Vec::new();
        HexKeyDetector::default().scan(text.as_bytes(), 0, &mut hits);
        hits.first().map(|h| h.confidence.get())
    }

    #[test]
    fn json_identifiers_are_noise_but_key_fields_are_not() {
        assert!(confidence(&format!("{{\"id\": \"{KEY}\", \"key\": \"x\"}}")).is_none_or(|c| c <= HEX_BLOCK_CONFIDENCE));
        assert!(confidence(&format!("{{\"privkey\": \"{KEY}\", \"seed\": 1}}")).is_some_and(|c| c > HEX_BLOCK_CONFIDENCE));
    }

    #[test]
    fn a_bare_hex_line_is_noise() {
        assert!(confidence(&format!("notes\n{KEY}\nend\n")).is_some_and(|c| c <= HEX_BLOCK_CONFIDENCE));
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;
    use strata_kernel::scan::Hit;

    const KEY: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";

    fn confidence(text: &str) -> Option<f32> {
        let mut hits: Vec<Hit> = Vec::new();
        HexKeyDetector::default().scan(text.as_bytes(), 0, &mut hits);
        hits.first().map(|h| h.confidence.get())
    }

    #[test]
    fn a_common_word_far_away_says_nothing() {
        let filler = "lorem ipsum dolor sit amet ".repeat(4);
        assert_eq!(confidence(&format!("the key of the map {filler} value={KEY};")), None);
        assert!(confidence(&format!("key: {KEY};")).is_some_and(|c| c > HEX_BLOCK_CONFIDENCE));
    }

    #[test]
    fn a_strong_word_far_away_counts_like_a_weak_label() {
        let filler = "lorem ipsum dolor sit amet ".repeat(4);
        let far = confidence(&format!("my bitcoin {filler} value={KEY};")).unwrap();
        let near = confidence(&format!("bitcoin privkey={KEY};")).unwrap();
        assert!(far < near, "{far} {near}");
    }

    #[test]
    fn zero_padded_values_are_not_keys() {
        assert_eq!(confidence(&format!("privkey: 00000000{}", &KEY[8..])), None);
        assert_eq!(confidence(&format!("privkey: {}00000000", &KEY[..56])), None);
        assert!(confidence(&format!("privkey: {KEY}")).is_some());
    }
}
