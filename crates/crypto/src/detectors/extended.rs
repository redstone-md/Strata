//! BIP32 extended keys (xprv/xpub and SLIP-132 variants) in ASCII and UTF-16LE.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::{hit, scored};
use super::text::{RunScanner, ALNUM, ASCII_UTF16LE};
use crate::keys::bip32::{DerivationPlan, ExtendedKey, KeyVersion, EXTENDED_KEY_TEXT_LEN};
use crate::keys::Wif;
use serde_json::json;
use strata_kernel::scan::{Detector, HitCategory, HitSink};

pub struct ExtendedKeyDetector {
    scanner: RunScanner,
    plan: DerivationPlan,
}

impl Default for ExtendedKeyDetector {
    fn default() -> Self {
        Self::new(DerivationPlan::new(3))
    }
}

impl ExtendedKeyDetector {
    pub fn new(plan: DerivationPlan) -> Self {
        Self { scanner: RunScanner::new(&ALNUM, EXTENDED_KEY_TEXT_LEN, EXTENDED_KEY_TEXT_LEN), plan }
    }

    fn prefix_ok(text: &[u8]) -> bool {
        let Some(head) = text.get(..4) else { return false };
        KeyVersion::all_prefixes().any(|p| p.as_bytes() == head)
    }
}

impl Detector for ExtendedKeyDetector {
    fn id(&self) -> &'static str {
        "crypto.extended_key"
    }

    fn max_match(&self) -> usize {
        self.scanner.max_bytes()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.scanner.scan(chunk, ASCII_UTF16LE, |run| {
            if !Self::prefix_ok(run.text) {
                return;
            }
            let Some(key) = ExtendedKey::parse(run.text) else { return };
            let version = key.version();
            let ctx = Context::around(chunk, run.start, run.start + run.byte_len, CONTEXT_RADIUS, run.encoding);
            let kind = if key.is_private() { "private" } else { "public" };
            let details = json!({
                "encoding": run.encoding.name(),
                "prefix": version.prefix(),
                "network": version.network().name(),
                "private": key.is_private(),
                "depth": key.depth(),
                "child_number": key.child_number(),
                "parent_fingerprint": hex::encode(key.parent_fingerprint()),
                "fingerprint": hex::encode(key.fingerprint()),
                "xpub": key.to_public().encode(),
                "key_wif": key.private_key().map(|k| Wif::new(*k, version.network(), true).encode()),
                "derived": self.plan.derive_json(&key),
                "context": ctx.to_json(),
            });
            let base_conf = if key.is_private() { 0.9 } else { 0.7 };
            sink.emit(
                hit(self.id(), HitCategory::ExtendedKey, base, run.start, run.byte_len)
                    .confidence(scored(base_conf, &ctx))
                    .label(format!("BIP32 {} {kind} key, depth {}", version.prefix(), key.depth()))
                    .value(String::from_utf8_lossy(run.text))
                    .details(details),
            );
        });
    }
}
