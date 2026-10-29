//! Fallback end-of-file search for types without usable size information: stop at the next
//! file header, at a long zero run (dense types), after the type's footer, or at the cap.

use serde::{Deserialize, Serialize};
use strata_identify::{ByteView, FileType, SignatureDetector};

const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    /// Another file's validated header starts here.
    NextHeader,
    /// A long run of zero bytes (dense formats never contain one).
    ZeroRun,
    /// Just past the type's footer bytes.
    Footer,
    /// Nothing found before the size cap / range end.
    Cap,
}

/// Searches forward from a file start for where it most likely ends.
pub struct BoundaryFinder<'a> {
    detector: &'a SignatureDetector,
    alignment: u64,
    zero_run: u64,
}

impl<'a> BoundaryFinder<'a> {
    pub fn new(detector: &'a SignatureDetector, alignment: u64, zero_run: u64) -> Self {
        Self { detector, alignment: alignment.max(1), zero_run: zero_run.max(512) }
    }

    /// End (relative to the view start) of the file of type `spec` that begins at 0.
    pub fn find(&self, spec: &FileType, view: &dyn ByteView) -> (u64, Boundary) {
        let limit = view.view_len();
        let mut chunk_at = 0u64;
        let mut zeros_from: Option<u64> = None;
        let mut footer_end: Option<u64> = None;
        while chunk_at < limit {
            // Overlap so headers/validation windows that straddle chunks are seen.
            let chunk = view.bytes(chunk_at, CHUNK + 64 * 1024);
            if chunk.is_empty() {
                break;
            }
            let body = chunk.len().min(CHUNK);
            let footers: Vec<u64> = spec
                .footer
                .map(|f| memchr::memmem::find_iter(&chunk[..body], f).map(|at| chunk_at + (at + f.len()) as u64).collect())
                .unwrap_or_default();
            let first = chunk_at.next_multiple_of(self.alignment).max(self.alignment);
            let mut pos = first;
            while pos < chunk_at + body as u64 && pos < limit {
                let rel = (pos - chunk_at) as usize;
                if self.detector.type_at(&chunk, rel).is_some() {
                    let footer = footers.iter().copied().filter(|f| *f <= pos).max().or(footer_end);
                    return match footer {
                        Some(f) => (f, Boundary::Footer),
                        None => (pos, Boundary::NextHeader),
                    };
                }
                pos += self.alignment;
            }
            footer_end = footers.last().copied().or(footer_end);
            if spec.dense {
                for (i, b) in chunk[..body].iter().enumerate() {
                    let at = chunk_at + i as u64;
                    if *b != 0 {
                        zeros_from = None;
                    } else if let Some(z) = zeros_from {
                        if at + 1 - z >= self.zero_run {
                            return (footer_end.unwrap_or(z), Boundary::ZeroRun);
                        }
                    } else {
                        zeros_from = Some(at);
                    }
                }
            }
            chunk_at += body as u64;
        }
        match footer_end {
            Some(end) => (end, Boundary::Footer),
            None => (limit, Boundary::Cap),
        }
    }
}
