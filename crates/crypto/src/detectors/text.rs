//! Text-run scanning shared by the Base58/hex detectors: ASCII, UTF-16LE and UTF-16BE.
//!
//! Runs are maximal sequences of a byte class. The scanner checks the last byte of each
//! candidate window first and skips past any non-class byte it finds, so random binary data
//! is skipped in strides close to `min` bytes instead of byte by byte.

use serde::Serialize;

/// Longest run the scanner can hand out (decoded to a stack buffer).
pub const MAX_RUN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    Ascii,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
        }
    }

    /// Bytes per code unit.
    pub fn unit(self) -> usize {
        match self {
            Encoding::Ascii => 1,
            Encoding::Utf16Le | Encoding::Utf16Be => 2,
        }
    }
}

/// A run found in the chunk, decoded to ASCII.
pub struct Run<'a> {
    /// Byte offset of the first unit within the chunk.
    pub start: usize,
    /// Length in bytes within the chunk.
    pub byte_len: usize,
    pub text: &'a [u8],
    pub encoding: Encoding,
}

/// Byte class lookup table.
pub type Class = [bool; 256];

pub const fn class_of(chars: &[u8]) -> Class {
    let mut t = [false; 256];
    let mut i = 0;
    while i < chars.len() {
        t[chars[i] as usize] = true;
        i += 1;
    }
    t
}

pub static ALNUM: Class =
    class_of(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
pub static HEX: Class = class_of(b"0123456789ABCDEFabcdef");

/// Finds runs of `class` with length in `min..=max` (in characters).
#[derive(Debug, Clone, Copy)]
pub struct RunScanner {
    class: &'static Class,
    min: usize,
    max: usize,
}

impl RunScanner {
    pub const fn new(class: &'static Class, min: usize, max: usize) -> Self {
        let max = if max > MAX_RUN { MAX_RUN } else { max };
        Self { class, min, max }
    }

    /// Longest match in bytes over every encoding.
    pub const fn max_bytes(&self) -> usize {
        self.max * 2
    }

    pub fn scan(&self, chunk: &[u8], encodings: &[Encoding], mut f: impl FnMut(&Run<'_>)) {
        for enc in encodings {
            match enc {
                Encoding::Ascii => self.scan_view(chunk, 0, *enc, &mut f),
                Encoding::Utf16Le | Encoding::Utf16Be => {
                    self.scan_view(chunk, 0, *enc, &mut f);
                    self.scan_view(chunk, 1, *enc, &mut f);
                }
            }
        }
    }

    /// ASCII value of unit `i` (0 when the unit is not a single ASCII char).
    #[inline(always)]
    fn unit(chunk: &[u8], align: usize, enc: Encoding, i: usize) -> u8 {
        match enc {
            Encoding::Ascii => chunk[i],
            Encoding::Utf16Le => {
                let at = align + 2 * i;
                if chunk[at + 1] == 0 { chunk[at] } else { 0 }
            }
            Encoding::Utf16Be => {
                let at = align + 2 * i;
                if chunk[at] == 0 { chunk[at + 1] } else { 0 }
            }
        }
    }

    fn scan_view(&self, chunk: &[u8], align: usize, enc: Encoding, f: &mut impl FnMut(&Run<'_>)) {
        let units = chunk.len().saturating_sub(align) / enc.unit();
        let class = self.class;
        let is = |i: usize| class[Self::unit(chunk, align, enc, i) as usize];
        let mut buf = [0u8; MAX_RUN];
        let mut p = 0usize;
        'outer: while p + self.min <= units {
            let mut q = p + self.min;
            while q > p {
                q -= 1;
                if !is(q) {
                    p = q + 1;
                    continue 'outer;
                }
            }
            let mut e = p + self.min;
            while e < units && is(e) {
                e += 1;
            }
            let len = e - p;
            if len <= self.max {
                for (k, slot) in buf[..len].iter_mut().enumerate() {
                    *slot = Self::unit(chunk, align, enc, p + k);
                }
                f(&Run {
                    start: align + p * enc.unit(),
                    byte_len: len * enc.unit(),
                    text: &buf[..len],
                    encoding: enc,
                });
            }
            p = e + 1;
        }
    }
}

/// Encodings scanned by most text detectors.
pub const ASCII_UTF16LE: &[Encoding] = &[Encoding::Ascii, Encoding::Utf16Le];

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn finds_bounded_runs() {
        let scanner = RunScanner::new(&ALNUM, 4, 6);
        let mut found = Vec::new();
        scanner.scan(b"ab, abcd; abcdefgh xyz12 q", &[Encoding::Ascii], |r| {
            found.push((r.start, String::from_utf8_lossy(r.text).to_string()))
        });
        assert_eq!(found, vec![(4, "abcd".into()), (19, "xyz12".into())]);
    }

    #[test]
    fn utf16_both_alignments() {
        let scanner = RunScanner::new(&ALNUM, 5, 5);
        let mut data = vec![0xffu8];
        data.extend(utf16le(" hello "));
        let mut found = Vec::new();
        scanner.scan(&data, ASCII_UTF16LE, |r| found.push((r.start, r.encoding, r.text.to_vec())));
        assert_eq!(found, vec![(3, Encoding::Utf16Le, b"hello".to_vec())]);
    }

    #[test]
    fn tiny_inputs() {
        let scanner = RunScanner::new(&ALNUM, 3, 8);
        for data in [&b""[..], b"a", b"ab", b"\x00"] {
            scanner.scan(data, &[Encoding::Ascii, Encoding::Utf16Le, Encoding::Utf16Be], |_| {});
        }
    }
}
