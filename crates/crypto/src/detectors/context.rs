//! Context scoring around a candidate: nearby wallet keywords and line isolation.

use super::keywords::{KeywordSet, Strength};
use super::text::Encoding;
use serde_json::{json, Value};

/// Default radius (bytes) searched on each side of a candidate.
pub const CONTEXT_RADIUS: usize = 256;

/// What surrounds a candidate.
#[derive(Debug, Default, Clone)]
pub struct Context {
    strong: bool,
    weak: bool,
    alone_on_line: bool,
    labels: Vec<&'static str>,
}

impl Context {
    /// Inspect `radius` bytes around `chunk[start..end]`.
    pub fn around(chunk: &[u8], start: usize, end: usize, radius: usize, enc: Encoding) -> Self {
        let lo = start.saturating_sub(radius);
        let hi = end.saturating_add(radius).min(chunk.len());
        let mut ctx = Context { alone_on_line: alone_on_line(chunk, start, end, enc), ..Default::default() };
        let Some(window) = chunk.get(lo..hi) else { return ctx };
        for (s, e, kw, _) in KeywordSet::get().find_iter(window) {
            let (s, e) = (lo + s, lo + e);
            if s < end && e > start {
                continue;
            }
            if kw.text.len() <= 4 && !word_bounded(chunk, s, e) {
                continue;
            }
            match kw.strength {
                Strength::Strong => ctx.strong = true,
                Strength::Weak => ctx.weak = true,
            }
            if !ctx.labels.contains(&kw.text) && ctx.labels.len() < 8 {
                ctx.labels.push(kw.text);
            }
        }
        ctx
    }

    pub fn strong(&self) -> bool {
        self.strong
    }

    pub fn weak(&self) -> bool {
        self.weak
    }

    pub fn alone_on_line(&self) -> bool {
        self.alone_on_line
    }

    pub fn any(&self) -> bool {
        self.strong || self.weak || self.alone_on_line
    }

    pub fn labels(&self) -> &[&'static str] {
        &self.labels
    }

    pub fn to_json(&self) -> Value {
        json!({
            "keywords": self.labels,
            "strong": self.strong,
            "alone_on_line": self.alone_on_line,
        })
    }
}

fn is_letter(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

/// ASCII-letter boundaries on both sides (works for UTF-8 and, via the NUL check, UTF-16LE).
fn word_bounded(chunk: &[u8], s: usize, e: usize) -> bool {
    let before = s.checked_sub(1).and_then(|i| chunk.get(i)).copied();
    let before = match before {
        Some(0) => s.checked_sub(2).and_then(|i| chunk.get(i)).copied(),
        other => other,
    };
    let after = chunk.get(e).copied();
    !before.is_some_and(is_letter) && !after.is_some_and(is_letter)
}

/// Only whitespace between the candidate and the surrounding line breaks.
pub fn alone_on_line(chunk: &[u8], start: usize, end: usize, enc: Encoding) -> bool {
    const LIMIT: usize = 64;
    let unit = enc.unit();
    let ws = |i: usize| -> Option<Option<bool>> {
        // Some(Some(true)) = newline, Some(Some(false)) = blank, Some(None) = other.
        let b = match enc {
            Encoding::Ascii => *chunk.get(i)?,
            Encoding::Utf16Le => {
                if *chunk.get(i + 1)? != 0 {
                    return Some(None);
                }
                *chunk.get(i)?
            }
            Encoding::Utf16Be => {
                if *chunk.get(i)? != 0 {
                    return Some(None);
                }
                *chunk.get(i + 1)?
            }
        };
        Some(match b {
            b'\n' | b'\r' | 0 => Some(true),
            b' ' | b'\t' => Some(false),
            _ => None,
        })
    };
    let mut ok_before = false;
    let mut i = start;
    for _ in 0..LIMIT {
        let Some(prev) = i.checked_sub(unit) else {
            ok_before = true;
            break;
        };
        match ws(prev) {
            None | Some(Some(true)) => {
                ok_before = true;
                break;
            }
            Some(Some(false)) => i = prev,
            Some(None) => break,
        }
    }
    if !ok_before {
        return false;
    }
    let mut j = end;
    for _ in 0..LIMIT {
        match ws(j) {
            None | Some(Some(true)) => return true,
            Some(Some(false)) => j += unit,
            Some(None) => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_context() {
        let data = b"my bitcoin privkey: AAAA end";
        let ctx = Context::around(data, 20, 24, 256, Encoding::Ascii);
        assert!(ctx.strong());
        assert!(ctx.labels().contains(&"bitcoin"));
        let ctx = Context::around(b"monkey AAAA", 7, 11, 256, Encoding::Ascii);
        assert!(!ctx.weak());
    }

    #[test]
    fn line_isolation() {
        let data = b"foo\n  AAAA \r\nbar";
        assert!(alone_on_line(data, 6, 10, Encoding::Ascii));
        assert!(!alone_on_line(b"x AAAA", 2, 6, Encoding::Ascii));
        assert!(alone_on_line(b"AAAA", 0, 4, Encoding::Ascii));
    }
}
