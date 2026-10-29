//! mbox files (Thunderbird, Linux mail spools, Opera `.mbs`): messages separated by
//! `From sender date` lines. Read in windows so multi-gigabyte inboxes never sit in memory.

use crate::lines::{is_separator, line_at};
use memchr::memmem;
use strata_kernel::Result;

/// A message's bytes inside its container (separator line excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub offset: u64,
    pub len: u64,
}

/// One message read from an mbox: where it is and its bytes (cut at the window size for a
/// message larger than the window).
#[derive(Debug, Clone)]
pub struct MboxMessage {
    pub span: Span,
    pub bytes: Vec<u8>,
    pub cut: bool,
}

/// Separator positions in `data`: at its start or after a line break.
fn separators(data: &[u8]) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    if is_separator(data, 0) {
        out.push(0);
    }
    out.extend(memmem::find_iter(data, b"\nFrom ").map(|p| p + 1).filter(|p| is_separator(data, *p)));
    out
}

/// Messages between separators of a window. Returns the complete ones and how many bytes of
/// the window they consumed; at end of file the last message is complete too. Text before the
/// first separator (a file cut at its start) counts as a message.
pub fn split(data: &[u8], at_eof: bool) -> (Vec<Span>, usize) {
    let seps = separators(data);
    let mut spans = Vec::new();
    let mut starts: Vec<(usize, usize)> = Vec::new(); // (separator, content start)
    if seps.first() != Some(&0) && data.iter().any(|b| !b.is_ascii_whitespace() && *b != 0) {
        starts.push((0, 0));
    }
    starts.extend(seps.iter().map(|&s| (s, line_at(data, s).1)));
    let mut consumed = 0;
    for (i, &(sep, content)) in starts.iter().enumerate() {
        let end = match starts.get(i + 1) {
            Some(&(next, _)) => next,
            None if at_eof => data.len(),
            None => {
                consumed = sep;
                break;
            }
        };
        consumed = end;
        let body = &data[content.min(end)..end];
        let trimmed = body.strip_suffix(b"\n").map_or(body, |b| b.strip_suffix(b"\r").unwrap_or(b));
        if !trimmed.is_empty() {
            spans.push(Span { offset: content as u64, len: trimmed.len() as u64 });
        }
    }
    (spans, consumed)
}

/// Reads an mbox through a `read(offset, buf)` function, a window at a time.
pub struct MboxReader<R> {
    read: R,
    len: u64,
    pos: u64,
    window: usize,
}

impl<R: FnMut(u64, &mut [u8]) -> Result<usize>> MboxReader<R> {
    /// Default window: messages up to this size are read whole.
    pub const WINDOW: usize = 32 << 20;

    /// Start at `pos` (0, or a position an earlier [`Self::position`] returned).
    pub fn new(read: R, len: u64, pos: u64, window: usize) -> Self {
        Self { read, len, pos, window: window.max(4096) }
    }

    /// Where the next batch starts: a separator, so reading can resume there.
    pub fn position(&self) -> u64 {
        self.pos
    }

    fn fill(&mut self, at: u64, max: usize) -> Result<Vec<u8>> {
        let want = (self.len.saturating_sub(at)).min(max as u64) as usize;
        let mut buf = vec![0u8; want];
        let n = (self.read)(at, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The messages of the next window; `None` at end of file.
    pub fn next_batch(&mut self) -> Result<Option<Vec<MboxMessage>>> {
        if self.pos >= self.len {
            return Ok(None);
        }
        let base = self.pos;
        let buf = self.fill(base, self.window)?;
        if buf.is_empty() {
            self.pos = self.len;
            return Ok(None);
        }
        let at_eof = base + buf.len() as u64 >= self.len;
        let (spans, consumed) = split(&buf, at_eof);
        if consumed == 0 && !at_eof {
            // One message larger than the window: keep its start, skip to the next separator.
            let (_, content) = line_at(&buf, 0);
            let content = if is_separator(&buf, 0) { content } else { 0 };
            let bytes = buf[content..].to_vec();
            self.pos = self.next_separator(base + buf.len() as u64)?;
            let span = Span { offset: base + content as u64, len: bytes.len() as u64 };
            return Ok(Some(vec![MboxMessage { span, bytes, cut: true }]));
        }
        self.pos = if at_eof { self.len } else { base + consumed as u64 };
        let out = spans
            .into_iter()
            .map(|s| {
                let bytes = buf[s.offset as usize..(s.offset + s.len) as usize].to_vec();
                MboxMessage { span: Span { offset: base + s.offset, len: s.len }, bytes, cut: false }
            })
            .collect();
        Ok(Some(out))
    }

    /// The first separator at or after `from` (searching window by window), else end of file.
    fn next_separator(&mut self, from: u64) -> Result<u64> {
        let mut at = from.saturating_sub(1);
        while at < self.len {
            let buf = self.fill(at, self.window)?;
            if buf.len() < 8 {
                break;
            }
            if let Some(p) = memmem::find_iter(&buf, b"\nFrom ").map(|p| p + 1).find(|p| is_separator(&buf, *p)) {
                return Ok(at + p as u64);
            }
            at += (buf.len() - 7) as u64;
        }
        Ok(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MBOX: &[u8] = b"From MAILER Sat May 14 17:36:09 2011\nFrom: a@example.com\nSubject: one\n\nbody one\nFrom here on\n\n\
From MAILER Sun May 15 10:00:00 2011\nFrom: b@example.com\nSubject: two\n\nbody two\n";

    #[test]
    fn splits_on_separators_only() {
        let (spans, consumed) = split(MBOX, true);
        assert_eq!(spans.len(), 2);
        assert_eq!(consumed, MBOX.len());
        let first = &MBOX[spans[0].offset as usize..(spans[0].offset + spans[0].len) as usize];
        assert!(first.starts_with(b"From: a@") && first.ends_with(b"From here on\n"));
        let (spans, consumed) = split(MBOX, false);
        assert_eq!(spans.len(), 1, "the last message may continue in the next window");
        assert_eq!(&MBOX[consumed..consumed + 11], b"From MAILER");
        let (spans, _) = split(b"ject: cut\nFrom: x@example.com\n\nrest", true);
        assert_eq!(spans.len(), 1, "a cut start is a message too");
        assert!(split(b"\0\0\0", true).0.is_empty());
    }

    fn read_all(data: &[u8], window: usize) -> Vec<MboxMessage> {
        let mut reader = MboxReader::new(
            |at: u64, buf: &mut [u8]| {
                let src = data.get(at as usize..).unwrap_or_default();
                let n = src.len().min(buf.len());
                buf[..n].copy_from_slice(&src[..n]);
                Ok(n)
            },
            data.len() as u64,
            0,
            window,
        );
        let mut out = Vec::new();
        while let Some(batch) = reader.next_batch().unwrap() {
            out.extend(batch);
        }
        out
    }

    #[test]
    fn windows_give_the_same_messages_and_cut_giants() {
        let mut data = MBOX.to_vec();
        for i in 0..40 {
            data.extend_from_slice(format!("From X Mon Jan 1 2011\nFrom: c{i}@example.com\nSubject: s{i}\n\n{}\n", "x".repeat(300)).as_bytes());
        }
        let whole = read_all(&data, 1 << 20);
        let small = read_all(&data, 4096);
        assert_eq!(whole.len(), 42);
        assert_eq!(whole.iter().map(|m| m.span).collect::<Vec<_>>(), small.iter().map(|m| m.span).collect::<Vec<_>>());
        let mut giant = b"From X Mon Jan 1 2011\nFrom: big@example.com\nSubject: big\n\n".to_vec();
        giant.extend(std::iter::repeat_n(b'y', 10_000));
        giant.extend_from_slice(b"\nFrom X Mon Jan 1 2011\nFrom: after@example.com\nSubject: after\n\nz\n");
        let got = read_all(&giant, 4096);
        assert_eq!(got.len(), 2);
        assert!(got[0].cut && got[0].bytes.len() < 4096);
        assert!(got[1].bytes.starts_with(b"From: after@"));
    }
}
