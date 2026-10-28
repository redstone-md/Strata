use serde::{Deserialize, Serialize};
use std::fmt;

/// Half-open byte interval `[start, start + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ByteRange {
    start: u64,
    len: u64,
}

impl ByteRange {
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    pub fn from_bounds(start: u64, end: u64) -> Self {
        Self { start, len: end.saturating_sub(start) }
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset < self.end()
    }

    pub fn intersect(&self, other: &ByteRange) -> Option<ByteRange> {
        let start = self.start.max(other.start);
        let end = self.end().min(other.end());
        (start < end).then(|| ByteRange::from_bounds(start, end))
    }

    pub fn shifted(&self, delta: u64) -> ByteRange {
        ByteRange::new(self.start.saturating_add(delta), self.len)
    }

    /// Merge ranges into sorted, non-overlapping, non-adjacent ranges.
    pub fn coalesce(mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
        ranges.retain(|r| !r.is_empty());
        ranges.sort();
        let mut out: Vec<ByteRange> = Vec::with_capacity(ranges.len());
        for r in ranges {
            match out.last_mut() {
                Some(last) if r.start <= last.end() => {
                    let end = last.end().max(r.end());
                    *last = ByteRange::from_bounds(last.start, end);
                }
                _ => out.push(r),
            }
        }
        out
    }

    /// Total length of `self` covered by `ranges` (which must not overlap each other).
    pub fn covered_by(&self, ranges: &[ByteRange]) -> u64 {
        ranges.iter().filter_map(|r| self.intersect(r)).map(|r| r.len).sum()
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}+{:#x}", self.start, self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_merges_overlaps_and_adjacent() {
        let out = ByteRange::coalesce(vec![
            ByteRange::new(10, 5),
            ByteRange::new(0, 10),
            ByteRange::new(30, 1),
            ByteRange::new(12, 10),
        ]);
        assert_eq!(out, vec![ByteRange::new(0, 22), ByteRange::new(30, 1)]);
    }

    #[test]
    fn intersect_and_cover() {
        let r = ByteRange::new(100, 100);
        assert_eq!(r.intersect(&ByteRange::new(150, 100)), Some(ByteRange::new(150, 50)));
        assert_eq!(r.intersect(&ByteRange::new(200, 1)), None);
        assert_eq!(r.covered_by(&[ByteRange::new(0, 110), ByteRange::new(190, 5)]), 15);
    }
}
