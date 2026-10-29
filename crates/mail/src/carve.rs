//! Messages in free space: a deleted `.eml` or a piece of an mbox whose clusters were freed.
//! A message starts at a header block ([`HeaderBlock::is_carvable`]) and ends at the closing
//! MIME boundary, an mbox separator, the next message's header block, a cluster of zero bytes
//! or the size cap — whichever comes first.

use crate::lines::{HeaderBlock, header_name, is_separator, line_at};
use memchr::memmem;

/// Largest message carved; anything longer is cut there.
pub const MAX_CARVED: usize = 8 << 20;
/// Zero bytes in a row that end a carved message (one cluster of never-written space).
const ZERO_END: usize = 4096;

/// Line starts in `data` where a carvable header block begins, in order and not overlapping.
pub fn message_starts(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let (line, next) = line_at(data, at);
        let first = line.first().copied().unwrap_or(0);
        if first.is_ascii_alphabetic() && header_name(line).is_some() {
            let block = HeaderBlock::at(data, at);
            if block.is_carvable() {
                out.push(at);
                at += block.len.max(1);
                continue;
            }
        }
        at = next.max(at + 1);
    }
    out
}

/// Length of the message at the start of `data` (which begins with its header block), and
/// whether an end was seen before the bytes ran out.
pub fn message_len(data: &[u8]) -> (usize, bool) {
    let data = &data[..data.len().min(MAX_CARVED)];
    let block = HeaderBlock::at(data, 0);
    let body = block.len.min(data.len());
    let zero_end = memmem::find(&data[body..], &[0u8; ZERO_END]).map(|p| body + p);
    if let Some(boundary) = boundary(&data[..body]) {
        let closing = format!("--{boundary}--");
        if let Some(p) = memmem::find(&data[body..], closing.as_bytes()).map(|p| body + p) {
            let end = line_at(data, p).1;
            if zero_end.is_none_or(|z| z > p) {
                return (end, true);
            }
        }
    }
    let limit = zero_end.unwrap_or(data.len());
    let mut at = body;
    let mut blank_before = true;
    while at < limit {
        let (line, next) = line_at(data, at);
        if is_separator(data, at) || (blank_before && HeaderBlock::at(data, at).is_carvable()) {
            return (trim_end(data, at), true);
        }
        blank_before = line.is_empty();
        at = next;
    }
    (trim_end(data, limit), zero_end.is_some() || data.len() == MAX_CARVED)
}

/// `end` without the trailing line breaks.
fn trim_end(data: &[u8], end: usize) -> usize {
    let mut end = end.min(data.len());
    while end > 0 && matches!(data[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    end
}

/// The multipart boundary declared in a header block.
fn boundary(headers: &[u8]) -> Option<String> {
    let lower = headers.to_ascii_lowercase();
    let p = memmem::find(&lower, b"boundary=")? + 9;
    let rest = headers.get(p..)?;
    let value: Vec<u8> = match rest.first()? {
        b'"' => rest[1..].iter().take_while(|b| **b != b'"' && **b != b'\n').copied().collect(),
        _ => rest.iter().take_while(|b| !b";\r\n \t".contains(b)).copied().collect(),
    };
    (!value.is_empty()).then(|| String::from_utf8_lossy(&value).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"Received: from x\r\nFrom: a@example.com\r\nDate: Mon, 1 Jan 2011 10:00:00 +0000\r\nSubject: one\r\n\r\nfirst body\r\n";
    const B: &[u8] = b"Message-ID: <b@example.com>\r\nFrom: b@example.com\r\nSubject: two\r\n\r\nsecond body\r\n";

    #[test]
    fn finds_starts_and_ends() {
        let mut data = b"noise noise\n".to_vec();
        data.extend_from_slice(A);
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(B);
        data.extend(std::iter::repeat_n(0u8, ZERO_END));
        data.extend_from_slice(b"old junk");
        let starts = message_starts(&data);
        assert_eq!(starts, vec![12, 12 + A.len() + 2]);
        let (len, ended) = message_len(&data[starts[0]..]);
        assert!(ended);
        assert_eq!(&data[starts[0]..starts[0] + len], &A[..A.len() - 2]);
        let (len, ended) = message_len(&data[starts[1]..]);
        assert!(ended && data[starts[1]..starts[1] + len].ends_with(b"second body"));
        let (len, ended) = message_len(B);
        assert!(!ended && len == B.len() - 2, "ran out of bytes without an end");
    }

    #[test]
    fn multipart_ends_at_its_closing_boundary() {
        let msg = b"Date: Mon, 1 Jan 2011 10:00:00 +0000\r\nFrom: a@example.com\r\nSubject: s\r\n\
Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n--XX\r\nContent-Type: message/rfc822\r\n\r\n\
Date: Mon, 1 Jan 2011\r\nFrom: inner@example.com\r\nSubject: inner\r\n\r\ninner body\r\n--XX--\r\nafter";
        let (len, ended) = message_len(msg);
        assert!(ended);
        assert!(msg[..len].ends_with(b"--XX--\r\n"));
        // The inner block is a start too; callers skip starts inside a message already carved.
        assert_eq!(message_starts(msg)[0], 0);
        assert_eq!(boundary(b"Content-Type: multipart/mixed; boundary=abc;\r\n"), Some("abc".into()));
        assert_eq!(message_len(b""), (0, false));
    }
}
