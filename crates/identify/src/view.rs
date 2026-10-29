//! Random-access byte view shared by in-memory buffers and evidence sources, so structure
//! walkers (used for both identification and carving) are written once.

use memchr::memmem;

const SEARCH_CHUNK: usize = 1 << 20;

pub trait ByteView {
    fn view_len(&self) -> u64;

    /// Copy bytes at `off` into `buf`; returns the number produced (short at the end).
    fn read_into(&self, off: u64, buf: &mut [u8]) -> usize;

    /// Up to `len` bytes at `off` (shorter at the end of the view).
    fn bytes(&self, off: u64, len: usize) -> Vec<u8> {
        let avail = self.view_len().saturating_sub(off).min(len as u64) as usize;
        let mut buf = vec![0u8; avail];
        let n = self.read_into(off, &mut buf);
        buf.truncate(n);
        buf
    }

    /// First occurrence of `needle` starting in `[from, to)`.
    fn find(&self, needle: &[u8], from: u64, to: u64) -> Option<u64> {
        let to = to.min(self.view_len());
        let overlap = needle.len().saturating_sub(1) as u64;
        let finder = memmem::Finder::new(needle);
        let mut pos = from;
        while pos < to {
            let want = (to - pos + overlap).min(SEARCH_CHUNK as u64 + overlap) as usize;
            let chunk = self.bytes(pos, want);
            if let Some(i) = finder.find(&chunk) {
                let at = pos + i as u64;
                return (at < to).then_some(at);
            }
            if chunk.len() < needle.len() {
                return None;
            }
            pos += (chunk.len() as u64).saturating_sub(overlap).max(1);
        }
        None
    }

    /// Every occurrence of `needle` starting in `[from, to)`, at most `limit` of them.
    fn find_all(&self, needle: &[u8], from: u64, to: u64, limit: usize) -> Vec<u64> {
        let mut out = Vec::new();
        let mut pos = from;
        while out.len() < limit {
            match self.find(needle, pos, to) {
                Some(at) => {
                    out.push(at);
                    pos = at + 1;
                }
                None => break,
            }
        }
        out
    }
}

impl ByteView for &[u8] {
    fn view_len(&self) -> u64 {
        self.len() as u64
    }

    fn read_into(&self, off: u64, buf: &mut [u8]) -> usize {
        let Ok(off) = usize::try_from(off) else { return 0 };
        let src = self.get(off..).unwrap_or_default();
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        n
    }

    fn bytes(&self, off: u64, len: usize) -> Vec<u8> {
        let Ok(off) = usize::try_from(off) else { return Vec::new() };
        let src = self.get(off..).unwrap_or_default();
        src[..src.len().min(len)].to_vec()
    }

    fn find(&self, needle: &[u8], from: u64, to: u64) -> Option<u64> {
        let from = usize::try_from(from).ok()?;
        let to = usize::try_from(to.min(self.view_len())).ok()?;
        let hay = self.get(from..(to + needle.len()).saturating_sub(1).min(self.len()))?;
        memmem::find(hay, needle).map(|i| (from + i) as u64).filter(|at| *at < to as u64)
    }
}

/// Cached sequential reader for walkers that read many small fields (GIF sub-blocks, JPEG
/// entropy data) from a view that may be backed by slow evidence I/O.
pub struct Buffered<'a> {
    view: &'a dyn ByteView,
    at: u64,
    cache: Vec<u8>,
}

impl<'a> Buffered<'a> {
    const CACHE: usize = 256 * 1024;

    pub fn new(view: &'a dyn ByteView) -> Self {
        Self { view, at: 0, cache: Vec::new() }
    }

    pub fn len(&self) -> u64 {
        self.view.view_len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn fill(&mut self, off: u64, need: usize) -> bool {
        let have = off >= self.at && off + need as u64 <= self.at + self.cache.len() as u64;
        if !have {
            self.at = off;
            self.cache = self.view.bytes(off, Self::CACHE.max(need));
        }
        off + need as u64 <= self.at + self.cache.len() as u64
    }

    pub fn byte(&mut self, off: u64) -> Option<u8> {
        self.fill(off, 1).then(|| self.cache[(off - self.at) as usize])
    }

    /// `len` bytes at `off` (shorter at the end of the view).
    pub fn slice(&mut self, off: u64, len: usize) -> &[u8] {
        let len = len.min(self.len().saturating_sub(off) as usize);
        if !self.fill(off, len) {
            return &[];
        }
        let start = (off - self.at) as usize;
        &self.cache[start..start + len]
    }
}

/// A sub-window of another view, re-based at zero.
pub struct SubView<'a> {
    inner: &'a dyn ByteView,
    start: u64,
    len: u64,
}

impl<'a> SubView<'a> {
    pub fn new(inner: &'a dyn ByteView, start: u64, len: u64) -> Self {
        let len = len.min(inner.view_len().saturating_sub(start));
        Self { inner, start, len }
    }
}

impl ByteView for SubView<'_> {
    fn view_len(&self) -> u64 {
        self.len
    }

    fn read_into(&self, off: u64, buf: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let n = buf.len().min((self.len - off) as usize);
        self.inner.read_into(self.start + off, &mut buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Chunky(Vec<u8>);

    impl ByteView for Chunky {
        fn view_len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_into(&self, off: u64, buf: &mut [u8]) -> usize {
            self.0.as_slice().read_into(off, buf)
        }
    }

    #[test]
    fn find_across_chunk_boundary() {
        let mut data = vec![0u8; SEARCH_CHUNK * 2 + 10];
        data[SEARCH_CHUNK - 2..SEARCH_CHUNK + 2].copy_from_slice(b"ABCD");
        let v = Chunky(data.clone());
        assert_eq!(v.find(b"ABCD", 0, v.view_len()), Some((SEARCH_CHUNK - 2) as u64));
        assert_eq!(data.as_slice().find(b"ABCD", 0, data.len() as u64), Some((SEARCH_CHUNK - 2) as u64));
        assert_eq!(v.find(b"ABCD", SEARCH_CHUNK as u64, v.view_len()), None);
        assert_eq!(v.find_all(b"\0\0", 0, 4, 10), vec![0, 1, 2, 3]);
    }
}
