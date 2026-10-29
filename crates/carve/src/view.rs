//! [`ByteView`] over a window of a [`BlockSource`], so identify's structure walkers run
//! directly against evidence.

use strata_identify::ByteView;
use strata_source::BlockSource;

pub struct SourceView<'a> {
    source: &'a dyn BlockSource,
    start: u64,
    len: u64,
}

impl<'a> SourceView<'a> {
    /// Window `[start, start + len)` clamped to the source.
    pub fn new(source: &'a dyn BlockSource, start: u64, len: u64) -> Self {
        let len = len.min(source.len().saturating_sub(start));
        Self { source, start, len }
    }
}

impl ByteView for SourceView<'_> {
    fn view_len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, off: u64, buf: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let n = buf.len().min((self.len - off) as usize);
        // Unreadable areas come back zero-filled from the source; an I/O error reads as nothing.
        self.source.read_at(self.start + off, &mut buf[..n]).unwrap_or(0)
    }
}
