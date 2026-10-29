//! Binary SEC1/OpenSSL DER private keys (Bitcoin Core `key` records, OpenSSL dumps,
//! KeyHunter output). Prefiltered by SIMD search for the common `02 01 01 04 20` core.

use super::report::{hit, key_details, with};
use crate::keys::der::{DerKey, DER_CORE, MAX_DER_LEN};
use crate::keys::Network;
use memchr::memmem::Finder;
use serde_json::json;
use std::sync::LazyLock;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

static CORE: LazyLock<Finder<'static>> = LazyLock::new(|| Finder::new(DER_CORE));

#[derive(Default)]
pub struct DerKeyDetector;

impl DerKeyDetector {
    fn confidence(key: &DerKey) -> Option<(Confidence, &'static str)> {
        match (key.pubkey_match(), key.curve_ok()) {
            (Some(true), _) => Some((Confidence::new(0.95), "public key verified")),
            (None, true) => Some((Confidence::new(0.5), "curve OID ok, no public key")),
            (Some(false), true) => Some((Confidence::new(0.2), "embedded public key mismatch")),
            _ => None,
        }
    }
}

impl Detector for DerKeyDetector {
    fn id(&self) -> &'static str {
        "crypto.der_key"
    }

    fn max_match(&self) -> usize {
        MAX_DER_LEN
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        for core_at in CORE.find_iter(chunk) {
            let Some((start, key)) = DerKey::parse_around_core(chunk, core_at) else { continue };
            let Some((confidence, note)) = Self::confidence(&key) else { continue };
            let keyhunter = start.checked_sub(1).and_then(|i| chunk.get(i)) == Some(&0x01)
                && key.encoded_len() == 279;
            let (start, len) = if keyhunter { (start - 1, key.encoded_len() + 1) } else { (start, key.encoded_len()) };
            let mut label = format!("DER private key ({})", key.form().name());
            if keyhunter {
                label.push_str(", KeyHunter prefix");
            }
            let details = with(
                key_details(key.key(), Network::Mainnet, Some(key.compressed())),
                json!({
                    "form": key.form(),
                    "curve_ok": key.curve_ok(),
                    "pubkey_match": key.pubkey_match(),
                    "keyhunter": keyhunter,
                    "note": note,
                }),
            );
            sink.emit(
                hit(self.id(), HitCategory::PrivateKey, base, start, len)
                    .confidence(confidence)
                    .label(label)
                    .value(key.key().to_hex())
                    .details(details),
            );
        }
    }
}
