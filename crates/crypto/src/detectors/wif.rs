//! WIF private keys in ASCII and UTF-16LE text.

use super::context::{Context, CONTEXT_RADIUS};
use super::report::{hit, key_details, scored, with};
use super::text::{RunScanner, ALNUM, ASCII_UTF16LE};
use crate::keys::{base58, Wif};
use serde_json::json;
use strata_kernel::scan::{Detector, HitCategory, HitSink};

/// `[59]` + 50 or `[KLc]` + 51 Base58 chars, bounded by non-alphanumerics, checksum-valid.
pub struct WifDetector {
    scanner: RunScanner,
}

impl Default for WifDetector {
    fn default() -> Self {
        Self { scanner: RunScanner::new(&ALNUM, 51, 52) }
    }
}

impl WifDetector {
    fn shape_ok(text: &[u8]) -> bool {
        match (text.first(), text.len()) {
            (Some(b'5' | b'9'), 51) | (Some(b'K' | b'L' | b'c'), 52) => base58::is_base58(text),
            _ => false,
        }
    }
}

impl Detector for WifDetector {
    fn id(&self) -> &'static str {
        "crypto.wif"
    }

    fn max_match(&self) -> usize {
        self.scanner.max_bytes()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.scanner.scan(chunk, ASCII_UTF16LE, |run| {
            if !Self::shape_ok(run.text) {
                return;
            }
            let Some(wif) = Wif::parse(run.text) else { return };
            let end = run.start + run.byte_len;
            let ctx = Context::around(chunk, run.start, end, CONTEXT_RADIUS, run.encoding);
            let details = with(
                key_details(wif.key(), wif.network(), Some(wif.compressed())),
                json!({ "encoding": run.encoding.name(), "context": ctx.to_json() }),
            );
            sink.emit(
                hit(self.id(), HitCategory::PrivateKey, base, run.start, run.byte_len)
                    .confidence(scored(0.9, &ctx))
                    .label(wif.describe())
                    .value(wif.encode())
                    .details(details),
            );
        });
    }
}
