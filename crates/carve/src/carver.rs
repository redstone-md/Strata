//! Carve one file out of raw evidence: find its length from the type's own size information,
//! fall back to boundary search, then identify the carved bytes.

use crate::boundary::{Boundary, BoundaryFinder};
use crate::view::SourceView;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_identify::{Identifier, MeasureMethod, SignatureDetector, TypeId, TypeVerdict, measure};
use strata_kernel::{ByteRange, Damage, DamageKind, Error, Result};
use strata_source::BlockSource;

/// How the carved length was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum LengthSource {
    /// The format's own size information (header field, chain walk, footer).
    Structure(MeasureMethod),
    /// No size information: boundary search.
    Boundary(Boundary),
}

impl LengthSource {
    pub fn is_exact(self) -> bool {
        matches!(self, LengthSource::Structure(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFile {
    /// Absolute range in the source.
    pub range: ByteRange,
    /// Type the carve was requested for (the verdict may refine it, e.g. zip -> docx).
    pub file_type: TypeId,
    pub length: LengthSource,
    pub verdict: TypeVerdict,
    /// Source-level damage inside `range` (absolute) plus carving notes.
    pub damage: Vec<Damage>,
}

#[derive(Debug, Clone, Copy)]
pub struct CarveOptions {
    /// Bytes of a carved file read for its verdict.
    pub verify_limit: usize,
    /// Alignment of positions examined for the next header during boundary search.
    pub alignment: u64,
    /// Zero bytes in a row that end a dense file without size information.
    pub zero_run: u64,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self { verify_limit: 64 << 20, alignment: 512, zero_run: 64 * 1024 }
    }
}

pub struct Carver {
    source: Arc<dyn BlockSource>,
    identifier: Identifier,
    detector: SignatureDetector,
    options: CarveOptions,
}

impl Carver {
    pub fn new(source: Arc<dyn BlockSource>) -> Self {
        Self::with_options(source, CarveOptions::default())
    }

    pub fn with_options(source: Arc<dyn BlockSource>, options: CarveOptions) -> Self {
        Self { source, identifier: Identifier::new(), detector: SignatureDetector::new(), options }
    }

    pub fn source(&self) -> &Arc<dyn BlockSource> {
        &self.source
    }

    /// Carve a file of `file_type` starting at absolute `start`.
    pub fn carve(&self, start: u64, file_type: TypeId) -> Result<CarvedFile> {
        self.carve_within(start, file_type, self.source.len())
    }

    /// Like [`Carver::carve`] but never past absolute offset `end` (e.g. the end of an
    /// unallocated run).
    pub fn carve_within(&self, start: u64, file_type: TypeId, end: u64) -> Result<CarvedFile> {
        let src_len = self.source.len();
        if start >= src_len || start >= end {
            return Err(Error::OutOfRange { offset: start, len: 0 });
        }
        let spec = file_type.spec();
        let limit = spec.max_size.min(end.min(src_len) - start);
        let view = SourceView::new(self.source.as_ref(), start, limit);
        let mut damage = Vec::new();
        let (len, length) = match measure(file_type, &view, limit) {
            Some(m) => {
                if m.clipped {
                    damage.push(Damage::new(
                        DamageKind::Truncated,
                        Some(ByteRange::new(start, m.len)),
                        format!("{} declares more data than the {} bytes available here", spec.name, limit),
                    ));
                }
                (m.len, LengthSource::Structure(m.method))
            }
            None => {
                let finder = BoundaryFinder::new(&self.detector, self.options.alignment, self.options.zero_run);
                let (len, how) = finder.find(spec, &view);
                (len, LengthSource::Boundary(how))
            }
        };
        let range = ByteRange::new(start, len.max(1).min(limit));
        let verdict = self.verdict(range)?;
        if (range.len() as usize) > self.options.verify_limit {
            damage.push(Damage::new(
                DamageKind::Missing,
                None,
                format!("verdict computed on the first {} bytes only", self.options.verify_limit),
            ));
        }
        for bad in self.source.damage().iter().filter_map(|d| d.intersect(&range)) {
            damage.push(Damage::new(DamageKind::Unreadable, Some(bad), "unreadable source area (zero-filled)"));
        }
        Ok(CarvedFile { range, file_type, length, verdict, damage })
    }

    fn verdict(&self, range: ByteRange) -> Result<TypeVerdict> {
        let n = (range.len() as usize).min(self.options.verify_limit);
        let bytes = self.source.read_vec(range.start(), n)?;
        Ok(self.identifier.identify(&bytes, None))
    }

    /// Read the carved bytes (at most `limit`).
    pub fn read(&self, file: &CarvedFile, limit: usize) -> Result<Vec<u8>> {
        self.source.read_vec(file.range.start(), (file.range.len() as usize).min(limit))
    }
}
