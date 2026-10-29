//! Carve every signature hit that falls inside the given (typically unallocated) ranges.

use crate::carver::{CarvedFile, Carver};
use std::sync::Arc;
use strata_identify::TypeId;
use strata_kernel::ByteRange;
use strata_kernel::scan::{Hit, HitCategory};
use strata_source::BlockSource;

/// A file start taken from a signature hit.
#[derive(Debug, Clone, Copy)]
struct Start {
    offset: u64,
    file_type: TypeId,
    confidence: f32,
}

fn starts(hits: &[Hit]) -> Vec<Start> {
    let mut out: Vec<Start> = hits
        .iter()
        .filter(|h| h.category == HitCategory::FileSignature)
        .filter_map(|h| {
            let file_type = TypeId::from_key(h.details.get("type_id")?.as_str()?)?;
            Some(Start { offset: h.offset, file_type, confidence: h.confidence.get() })
        })
        .collect();
    out.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.confidence.total_cmp(&a.confidence)));
    out.dedup_by_key(|s| s.offset);
    out
}

impl Carver {
    /// Carve hits that start inside `ranges`, each bounded by its range. A hit inside an
    /// already carved file (embedded thumbnail, nested archive member) is skipped.
    pub fn carve_ranges(&self, ranges: &[ByteRange], hits: &[Hit]) -> Vec<CarvedFile> {
        let ranges = ByteRange::coalesce(ranges.to_vec());
        let mut out: Vec<CarvedFile> = Vec::new();
        let mut covered_until = 0u64;
        for s in starts(hits) {
            if s.offset < covered_until {
                continue;
            }
            let idx = ranges.partition_point(|r| r.end() <= s.offset);
            let Some(range) = ranges.get(idx).filter(|r| r.contains(s.offset)) else { continue };
            if let Ok(file) = self.carve_within(s.offset, s.file_type, range.end()) {
                covered_until = file.range.end();
                out.push(file);
            }
        }
        out
    }
}

/// Convenience wrapper: carve `hits` inside `ranges` of `source` with default options.
pub fn carve_ranges(source: Arc<dyn BlockSource>, ranges: &[ByteRange], hits: &[Hit]) -> Vec<CarvedFile> {
    Carver::new(source).carve_ranges(ranges, hits)
}
