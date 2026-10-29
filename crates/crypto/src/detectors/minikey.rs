//! Casascius mini private keys: `S` + 21 or 29 Base58 chars with `sha256(key + "?")[0] == 0`.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::{hit, key_details, scored, with};
use super::text::{Encoding, RunScanner, ALNUM};
use crate::keys::hash::sha256;
use crate::keys::{base58, Network, PrivateKey};
use serde_json::json;
use strata_kernel::scan::{Detector, HitCategory, HitSink};

const ENCODINGS: &[Encoding] = &[Encoding::Ascii, Encoding::Utf16Le, Encoding::Utf16Be];

pub struct MinikeyDetector {
    scanner: RunScanner,
}

impl Default for MinikeyDetector {
    fn default() -> Self {
        Self { scanner: RunScanner::new(&ALNUM, 22, 30) }
    }
}

/// Validate a minikey and return its private key.
pub fn minikey_to_key(text: &[u8]) -> Option<PrivateKey> {
    if !matches!(text.len(), 22 | 30) || text.first() != Some(&b'S') || !base58::is_base58(text) {
        return None;
    }
    let mut probe = [0u8; 31];
    let probe = probe.get_mut(..text.len() + 1)?;
    probe[..text.len()].copy_from_slice(text);
    probe[text.len()] = b'?';
    if sha256(probe)[0] != 0 {
        return None;
    }
    PrivateKey::from_bytes(&sha256(text))
}

impl Detector for MinikeyDetector {
    fn id(&self) -> &'static str {
        "crypto.minikey"
    }

    fn max_match(&self) -> usize {
        self.scanner.max_bytes()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.scanner.scan(chunk, ENCODINGS, |run| {
            let Some(key) = minikey_to_key(run.text) else { return };
            let ctx = Context::around(chunk, run.start, run.start + run.byte_len, CONTEXT_RADIUS, run.encoding);
            // 1/256 of random `S...` strings pass the typo check; 30-char keys are the norm.
            let base_conf = if run.text.len() == 30 { 0.55 } else { 0.35 };
            let details = with(
                key_details(&key, Network::Mainnet, Some(false)),
                json!({ "encoding": run.encoding.name(), "context": ctx.to_json() }),
            );
            sink.emit(
                hit(self.id(), HitCategory::PrivateKey, base, run.start, run.byte_len)
                    .confidence(scored(base_conf, &ctx))
                    .label(format!("Casascius minikey ({} chars)", run.text.len()))
                    .value(String::from_utf8_lossy(run.text))
                    .details(details),
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AddressSet;

    #[test]
    fn casascius_vector() {
        let key = minikey_to_key(b"SzavMBLoXU6kDrqtUVmffv").unwrap();
        let set = AddressSet::from_private_key(&key, Network::Mainnet);
        // Bitcoin wiki "Mini private key format" example.
        assert_eq!(key.to_hex(), "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262");
        let wif = crate::keys::Wif::new(key, Network::Mainnet, false).encode();
        assert_eq!(wif, "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF");
        assert_eq!(set.p2pkh_uncompressed(), "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj");
        assert!(minikey_to_key(b"SzavMBLoXU6kDrqtUVmffw").is_none());
    }
}
