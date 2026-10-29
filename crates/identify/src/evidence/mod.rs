//! Headerless inference: when the header is missing, zeroed or corrupt, look for the type's
//! internal structures anywhere in the buffer and infer the type with confidence proportional
//! to the evidence.

mod containers;
mod media;

use crate::probe::Probe;
use strata_kernel::Confidence;

/// Highest confidence a headerless inference can reach.
pub const MAX_CONFIDENCE: f32 = 0.8;

type Scanner = fn(&[u8]) -> Option<Probe>;

/// Every structure scanner, defined once.
const SCANNERS: &[Scanner] = &[
    containers::zip,
    containers::sqlite,
    containers::bdb,
    containers::ole,
    containers::pdf,
    containers::pe,
    containers::mft,
    containers::regf,
    containers::evtx,
    media::jpeg,
    media::png,
    media::mp4,
];

/// Best structural inference for `data`, if any scanner found convincing evidence.
pub fn infer(data: &[u8]) -> Option<Probe> {
    SCANNERS
        .iter()
        .filter_map(|scan| scan(data))
        .map(|mut p| {
            p.confidence = Confidence::new(p.confidence.get().min(MAX_CONFIDENCE));
            p.note("type inferred from internal structures (header missing or damaged)");
            p
        })
        .max_by(|a, b| a.score().total_cmp(&b.score()))
}

/// Confidence growing with the amount of independent evidence: `base` for the minimum,
/// approaching `base + span` as `count` reaches `saturate`.
pub(crate) fn graded(base: f32, span: f32, count: usize, saturate: usize) -> Confidence {
    let f = (count.min(saturate) as f32) / saturate.max(1) as f32;
    Confidence::new(base + span * f)
}
