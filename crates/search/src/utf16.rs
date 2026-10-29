//! Runs of UTF-16 text inside raw bytes, decoded so a regex can run over them.

use crate::Encoding;

/// Shortest run worth decoding, in characters.
const MIN_RUN: usize = 4;

/// Characters that make up text runs: Latin, Greek, Cyrillic and common punctuation. Other
/// code points end a run (so binary noise does not decode into long CJK strings).
fn texty(unit: u16) -> bool {
    matches!(unit, 0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0xA0..=0x058F | 0x2010..=0x206F | 0x20AC | 0x2116)
}

/// One decoded run: its text and where each character came from.
pub struct Run {
    start: usize,
    text: String,
    /// Byte index in `text` of each character (each character is one 2-byte unit).
    char_at: Vec<usize>,
}

impl Run {
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Data byte range of the text byte range `[from, to)`.
    pub fn byte_span(&self, from: usize, to: usize) -> (usize, usize) {
        let first = self.char_at.partition_point(|b| *b < from);
        let last = self.char_at.partition_point(|b| *b < to);
        (self.start + first * 2, self.start + last * 2)
    }
}

/// Every run in `data`, at both byte alignments.
pub struct Utf16Runs;

impl Utf16Runs {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(data: &[u8], encoding: Encoding) -> Vec<Run> {
        let mut runs = Vec::new();
        for align in 0..2 {
            let mut current: Option<Run> = None;
            let units = data.get(align..).unwrap_or_default().chunks_exact(2).enumerate();
            for (i, pair) in units {
                let unit = if encoding == Encoding::Utf16Be { u16::from_be_bytes([pair[0], pair[1]]) } else { u16::from_le_bytes([pair[0], pair[1]]) };
                match (texty(unit), char::from_u32(u32::from(unit))) {
                    (true, Some(c)) => {
                        let run = current.get_or_insert_with(|| Run { start: align + i * 2, text: String::new(), char_at: Vec::new() });
                        run.char_at.push(run.text.len());
                        run.text.push(c);
                    }
                    _ => runs.extend(current.take().filter(|r| r.char_at.len() >= MIN_RUN)),
                }
            }
            runs.extend(current.take().filter(|r| r.char_at.len() >= MIN_RUN));
        }
        runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_runs_at_odd_offsets() {
        let mut data = vec![0xFFu8, 0xFF, 0xFF];
        data.extend(Encoding::Utf16Le.encode("Привет, world").unwrap());
        data.extend([0xFF, 0xFF]);
        let runs = Utf16Runs::new(&data, Encoding::Utf16Le);
        let run = runs.iter().find(|r| r.text() == "Привет, world").expect("run");
        assert_eq!(run.start, 3);
        let at = run.text().find("world").unwrap();
        assert_eq!(run.byte_span(at, at + 5), (3 + 16, 3 + 26));
    }
}
