//! Mainnet addresses in text: Base58 `1...`/`3...` and bech32/bech32m `bc1...`.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::hit;
use super::text::{RunScanner, ALNUM, ASCII_UTF16LE};
use crate::keys::{Address, Network};
use serde_json::json;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

pub struct AddressDetector {
    scanner: RunScanner,
}

impl Default for AddressDetector {
    fn default() -> Self {
        Self { scanner: RunScanner::new(&ALNUM, 26, 62) }
    }
}

impl AddressDetector {
    fn shape_ok(text: &[u8]) -> bool {
        match text {
            [b'1' | b'3', ..] => text.len() <= 35,
            [b'b', b'c', b'1', ..] | [b'B', b'C', b'1', ..] => text.len() >= 42,
            _ => false,
        }
    }
}

impl Detector for AddressDetector {
    fn id(&self) -> &'static str {
        "crypto.address"
    }

    fn max_match(&self) -> usize {
        self.scanner.max_bytes()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.scanner.scan(chunk, ASCII_UTF16LE, |run| {
            if !Self::shape_ok(run.text) {
                return;
            }
            let Some(addr) = Address::parse(run.text) else { return };
            if addr.network() != Network::Mainnet {
                return;
            }
            let ctx = Context::around(chunk, run.start, run.start + run.byte_len, CONTEXT_RADIUS, run.encoding);
            let confidence = if ctx.strong() { 0.45 } else { 0.2 };
            sink.emit(
                hit(self.id(), HitCategory::Address, base, run.start, run.byte_len)
                    .confidence(Confidence::new(confidence))
                    .label(format!("address {}", addr.kind().name()))
                    .value(addr.as_str())
                    .details(json!({
                        "kind": addr.kind(),
                        "encoding": run.encoding.name(),
                        "context": ctx.to_json(),
                    })),
            );
        });
    }
}
