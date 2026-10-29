//! Wallet keyword markers (EN/RU; UTF-8, CP1251, UTF-16LE). Low confidence on their own;
//! the case layer uses them as context for nearby findings.

use super::keywords::KeywordSet;
use super::report::hit;
use serde_json::json;
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;

/// Repeats of the same marker closer than this are folded into the first one.
const FOLD_DISTANCE: usize = 256;
const MAX_MARKER_BYTES: usize = 64;

#[derive(Default)]
pub struct MarkerDetector;

fn letter_at(chunk: &[u8], i: Option<usize>) -> bool {
    i.and_then(|i| chunk.get(i)).is_some_and(|b| b.is_ascii_alphabetic())
}

impl Detector for MarkerDetector {
    fn id(&self) -> &'static str {
        "crypto.marker"
    }

    fn max_match(&self) -> usize {
        MAX_MARKER_BYTES
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let mut last: Vec<(&'static str, usize)> = Vec::new();
        for (s, e, kw, enc) in KeywordSet::markers().find_iter(chunk) {
            // Short ASCII markers (`seed`, `mkey`) must stand as words.
            if kw.text.len() <= 4 && (letter_at(chunk, s.checked_sub(1)) || letter_at(chunk, Some(e))) {
                continue;
            }
            match last.iter_mut().find(|(t, _)| *t == kw.text) {
                Some((_, at)) if s.saturating_sub(*at) < FOLD_DISTANCE => continue,
                Some((_, at)) => *at = s,
                None => last.push((kw.text, s)),
            }
            sink.emit(
                hit(self.id(), HitCategory::Marker, base, s, e - s)
                    .confidence(Confidence::new(0.1))
                    .label(format!("marker \"{}\" ({})", kw.text, enc.name()))
                    .value(kw.text)
                    .details(json!({ "encoding": enc.name(), "strength": format!("{:?}", kw.strength) })),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::keywords::encode_cp1251;

    #[test]
    fn finds_and_folds() {
        let mut data = b"my Bitcoin bitcoin wallet.dat; seedling seed.".to_vec();
        data.extend(encode_cp1251("мой кошелёк").unwrap());
        let mut hits = Vec::new();
        MarkerDetector.scan(&data, 10, &mut hits);
        let values: Vec<_> = hits.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(values, vec!["bitcoin", "wallet.dat", "seed", "кошелёк"]);
        assert_eq!(hits[0].offset, 13);
    }
}
