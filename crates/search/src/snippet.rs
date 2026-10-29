//! Display text for the bytes around a match, decoded in the match's encoding.

use crate::Encoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    pub preview: String,
    /// Character range of the match inside `preview`.
    pub match_from: u32,
    pub match_to: u32,
}

impl Snippet {
    /// `context` holds the match at `[at, at + len)`; everything is decoded with `encoding`
    /// (aligned to its code unit), control bytes shown as `·`.
    pub fn render(context: &[u8], at: usize, len: usize, encoding: Encoding) -> Self {
        let unit = encoding.unit();
        let at = at.min(context.len());
        let end = at.saturating_add(len).min(context.len());
        let before = context.get(at % unit..at).unwrap_or_default();
        let matched = context.get(at..end).unwrap_or_default();
        let after = context.get(end..).unwrap_or_default();
        let after = after.get(..after.len() - after.len() % unit).unwrap_or_default();
        let (b, m, a) = (encoding.decode(before), encoding.decode(matched), encoding.decode(after));
        let from = b.chars().count() as u32;
        let to = from + m.chars().count() as u32;
        Self { preview: format!("{b}{m}{a}"), match_from: from, match_to: to }
    }

    /// `(before, match, after)` of the preview, for emphasis when rendering.
    pub fn split(preview: &str, from: u32, to: u32) -> (String, String, String) {
        let chars: Vec<char> = preview.chars().collect();
        let (from, to) = ((from as usize).min(chars.len()), (to as usize).min(chars.len()));
        let from = from.min(to);
        (chars[..from].iter().collect(), chars[from..to].iter().collect(), chars[to..].iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_context_is_aligned() {
        let mut ctx = vec![0x41u8]; // odd byte before the aligned text
        ctx.extend(Encoding::Utf16Le.encode("ab секрет cd").unwrap());
        ctx.push(0x42);
        let at = 1 + 3 * 2;
        let s = Snippet::render(&ctx, at, 6 * 2, Encoding::Utf16Le);
        let (b, m, a) = Snippet::split(&s.preview, s.match_from, s.match_to);
        assert_eq!((b.as_str(), m.as_str(), a.as_str()), ("ab ", "секрет", " cd"));
    }

    #[test]
    fn control_bytes_are_hidden() {
        let s = Snippet::render(b"\x00\x01key\n", 2, 3, Encoding::Ascii);
        assert_eq!(s.preview, "··key·");
        assert_eq!((s.match_from, s.match_to), (2, 5));
    }
}
