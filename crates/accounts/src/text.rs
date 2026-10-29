//! Anchor-based text extraction over raw bytes. Instead of running a regex over every byte,
//! detectors find a rare anchor (`@`, `http`, `www.`) with memchr/memmem and expand around it,
//! in ASCII or UTF-16LE (`c 00 c 00 ...`) depending on how the anchor is encoded.

/// Text found around an anchor: narrowed to ASCII, with its raw byte span.
pub struct Span {
    pub start: usize,
    pub raw_len: usize,
    pub text: String,
    pub wide: bool,
}

/// Character stride at `pos`: 2 when the byte after it is NUL (UTF-16LE), else 1.
pub fn stride_at(data: &[u8], pos: usize) -> usize {
    if data.get(pos + 1) == Some(&0) && pos + 2 < data.len() { 2 } else { 1 }
}

/// Character at char index `i` relative to `pos` (negative = left), honouring the stride.
fn char_at(data: &[u8], pos: usize, stride: usize, i: isize) -> Option<u8> {
    let off = pos as isize + i * stride as isize;
    let off = usize::try_from(off).ok()?;
    let c = *data.get(off)?;
    if stride == 2 && data.get(off + 1) != Some(&0) {
        return None;
    }
    Some(c)
}

/// Expand from `pos` (inclusive) left while `left_ok` and right while `right_ok`, up to `max`
/// characters each side.
pub fn expand(
    data: &[u8],
    pos: usize,
    stride: usize,
    max: usize,
    left_ok: impl Fn(u8) -> bool,
    right_ok: impl Fn(u8) -> bool,
) -> Span {
    let mut left = 0isize;
    while (left as usize) < max && char_at(data, pos, stride, -(left + 1)).is_some_and(&left_ok) {
        left += 1;
    }
    let mut right = 0isize;
    while (right as usize) < max && char_at(data, pos, stride, right + 1).is_some_and(&right_ok) {
        right += 1;
    }
    let text: String = (-left..=right).filter_map(|i| char_at(data, pos, stride, i)).map(char::from).collect();
    let start = pos - left as usize * stride;
    Span { start, raw_len: text.len() * stride, text, wide: stride == 2 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ascii_and_wide() {
        let a = b"xx ab@cd.ef yy";
        let s = expand(a, 5, stride_at(a, 5), 64, |c| c.is_ascii_alphanumeric(), |c| c.is_ascii_alphanumeric() || c == b'.');
        assert_eq!((s.start, s.text.as_str()), (3, "ab@cd.ef"));
        let w: Vec<u8> = "x ab@cd.ef".bytes().flat_map(|b| [b, 0]).collect();
        let at = 8;
        let s = expand(&w, at, stride_at(&w, at), 64, |c| c.is_ascii_alphanumeric(), |c| c.is_ascii_alphanumeric() || c == b'.');
        assert_eq!((s.start, s.text.as_str(), s.raw_len, s.wide), (4, "ab@cd.ef", 16, true));
    }
}
