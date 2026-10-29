//! Line-level recognition of RFC 822 header blocks, shared by container sniffing, mbox
//! splitting and carving. Works on raw bytes: evidence text may be in any charset.

/// Header names that mark a mail header block.
const KNOWN: &[&str] = &[
    "from", "to", "cc", "subject", "date", "received", "message-id", "mime-version", "return-path", "delivered-to",
    "content-type", "reply-to", "x-mailer", "content-transfer-encoding", "sender", "in-reply-to", "references",
    "user-agent", "x-priority", "x-originating-ip",
];

/// Headers a quoted reply inside a body (`From:` / `Sent:` / `To:` / `Subject:`) never carries;
/// a carved header block needs one of them.
const STRONG: &[&str] = &["received", "message-id", "return-path", "mime-version", "delivered-to", "date", "x-mailer", "content-type"];

/// Lines looked at for one header block.
const MAX_LINES: usize = 400;

/// The name of a `Name: value` header line, if `line` is one.
pub(crate) fn header_name(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().take(80).position(|&b| b == b':')?;
    let name = &line[..colon];
    (!name.is_empty() && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')).then_some(name)
}

/// The line starting at `at` without its line break, and where the next line starts.
pub(crate) fn line_at(data: &[u8], at: usize) -> (&[u8], usize) {
    let rest = data.get(at..).unwrap_or_default();
    match memchr::memchr(b'\n', rest) {
        Some(n) => (rest[..n].strip_suffix(b"\r").unwrap_or(&rest[..n]), at + n + 1),
        None => (rest, data.len()),
    }
}

/// An mbox separator line (`From sender date`) followed by a header line.
pub(crate) fn is_separator(data: &[u8], at: usize) -> bool {
    let (line, next) = line_at(data, at);
    line.starts_with(b"From ") && line.len() <= 256 && header_name(line_at(data, next).0).is_some()
}

/// What the header lines at the start of some bytes look like.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HeaderBlock {
    pub lines: usize,
    pub known: usize,
    pub strong: usize,
    /// Bytes from the block start to the first body byte (or to where header lines stop).
    pub len: usize,
}

impl HeaderBlock {
    /// Measure the header lines at `at`; continuation lines extend the previous header.
    pub fn at(data: &[u8], at: usize) -> Self {
        let mut block = HeaderBlock { len: 0, ..Default::default() };
        let mut pos = at;
        for _ in 0..MAX_LINES {
            if pos >= data.len() {
                break;
            }
            let (line, next) = line_at(data, pos);
            if line.is_empty() {
                pos = next;
                break;
            }
            if line.starts_with(b" ") || line.starts_with(b"\t") {
                if block.lines == 0 {
                    break;
                }
            } else {
                let Some(name) = header_name(line) else { break };
                let name = String::from_utf8_lossy(name).to_ascii_lowercase();
                block.lines += 1;
                block.known += usize::from(KNOWN.contains(&name.as_str()));
                block.strong += usize::from(STRONG.contains(&name.as_str()));
            }
            pos = next;
        }
        block.len = pos - at;
        block
    }

    /// Enough to call the start of a file a message: two known headers.
    pub fn is_message(&self) -> bool {
        self.lines >= 2 && self.known >= 2
    }

    /// Enough to call text found in free space a message start: three header lines, two
    /// known ones and one a quoted reply never has.
    pub fn is_carvable(&self) -> bool {
        self.lines >= 3 && self.known >= 2 && self.strong >= 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_separators() {
        let msg = b"Received: by x\r\nFrom: a@example.com\r\nSubject: hi\r\n folded\r\n\r\nbody";
        let b = HeaderBlock::at(msg, 0);
        assert_eq!((b.lines, b.known, b.strong), (3, 3, 1));
        assert_eq!(&msg[b.len..], b"body");
        assert!(b.is_carvable() && b.is_message());
        let quoted = b"From: a\nSent: Monday\nTo: b\nSubject: re\n\n";
        assert!(!HeaderBlock::at(quoted, 0).is_carvable());
        assert!(!HeaderBlock::at(b"just words: here\nnot a header", 0).is_message());
        assert!(is_separator(b"From - Sat May 14 2011\nFrom: a@example.com\n", 0));
        assert!(!is_separator(b"From here on we walk\nand talk\n", 0));
        assert_eq!(line_at(b"ab", 0), (&b"ab"[..], 2));
        assert_eq!(header_name(b": x"), None);
        assert_eq!(HeaderBlock::at(b"", 5), HeaderBlock::default());
    }
}
