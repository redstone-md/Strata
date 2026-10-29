//! Sweeping byte ranges in resumable pieces (carving, content search). A piece is scanned a
//! little past its end so a match that crosses the cut is still seen; only matches that start
//! inside the piece are kept, so pieces give exactly the matches of one pass.

use serde::{Deserialize, Serialize};
use strata_engine::{ScanControl, Scanner};
use strata_kernel::scan::Hit;
use strata_kernel::{ByteRange, Result};
use strata_source::BlockSource;

/// How far a sweep over a list of ranges got.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SweepPos {
    /// Ranges finished.
    pub range: usize,
    /// Where the next piece of the current range starts (0: its beginning).
    pub offset: u64,
}

impl SweepPos {
    /// The next piece `(its whole range, start, end)`, at most `piece` bytes long.
    pub fn next(&self, ranges: &[ByteRange], piece: u64) -> Option<(ByteRange, u64, u64)> {
        let r = *ranges.get(self.range)?;
        let start = self.offset.max(r.start()).min(r.end());
        Some((r, start, start.saturating_add(piece.max(1)).min(r.end())))
    }

    /// Mark everything up to `end` of `range` done.
    pub fn advance(&mut self, range: ByteRange, end: u64) {
        if end >= range.end() {
            self.range += 1;
            self.offset = 0;
        } else {
            self.offset = end;
        }
    }
}

/// Hits of `scanner` that start in `[start, end)` of `range`. Progress goes to `control`.
pub(crate) fn scan_piece(
    scanner: &Scanner,
    source: &dyn BlockSource,
    range: ByteRange,
    (start, end): (u64, u64),
    control: &ScanControl,
) -> Result<Vec<Hit>> {
    let scan_end = end.saturating_add(scanner.overlap() as u64).min(range.end());
    let mut out = Vec::new();
    if start < scan_end {
        scanner.continue_ranges(source, &[ByteRange::from_bounds(start, scan_end)], control, |h| {
            out.extend(h.into_iter().filter(|h| h.offset >= start && h.offset < end));
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_ranges_in_pieces() {
        let ranges = [ByteRange::new(0, 10), ByteRange::new(100, 4)];
        let mut pos = SweepPos::default();
        let mut seen = Vec::new();
        while let Some((r, s, e)) = pos.next(&ranges, 4) {
            seen.push((s, e));
            pos.advance(r, e);
        }
        assert_eq!(seen, vec![(0, 4), (4, 8), (8, 10), (100, 104)]);
        assert_eq!(pos, SweepPos { range: 2, offset: 0 });
    }
}
