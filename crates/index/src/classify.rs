//! Fast per-block content classification for the streaming profiler.
//!
//! One histogram pass per block gives everything: zero/fill (exact, checked on every byte),
//! text share and encoding, and Shannon entropy. The histogram uses four interleaved tables
//! (no store-to-load stalls on runs of equal bytes) which also split counts by byte parity,
//! so UTF-16 detection needs no second pass. Thresholds follow `strata_identify`'s per-file
//! block profile (at least 97 % text-like bytes; entropy at least 93 % of the maximum).

use crate::record::{BlockClass, BlockRecord, TextKind};

/// Share of text-like bytes for a Text block.
const TEXT_RATIO: f32 = 0.97;
/// Share of the maximum entropy for a Random block.
const RANDOM_SHARE: f32 = 0.93;
/// Sampling window when only part of a block is histogrammed.
const WINDOW: usize = 1024;

/// Classifies blocks. `sample_every = 1` histograms every byte; `n` histograms one 1 KiB
/// window out of every `n` (zero/fill detection always looks at every byte).
#[derive(Debug, Clone, Copy)]
pub struct Classifier {
    sample_every: usize,
}

impl Default for Classifier {
    fn default() -> Self {
        Self { sample_every: 1 }
    }
}

impl Classifier {
    pub fn sampled(sample_every: usize) -> Self {
        Self { sample_every: sample_every.max(1) }
    }

    pub fn classify(&self, block: &[u8]) -> BlockRecord {
        let Some(&first) = block.first() else { return BlockRecord::content(BlockClass::Zero, TextKind::Ascii, 0.0) };
        if is_uniform(block, first) {
            let class = if first == 0 { BlockClass::Zero } else { BlockClass::Fill };
            return BlockRecord::content(class, TextKind::Ascii, 0.0);
        }
        let h = self.histogram(block);
        let entropy = h.entropy();
        if let Some(kind) = h.text_kind() {
            return BlockRecord::content(BlockClass::Text, kind, entropy);
        }
        let max = (h.total as f32).log2().min(8.0);
        let class = if entropy >= max * RANDOM_SHARE { BlockClass::Random } else { BlockClass::Binary };
        BlockRecord::content(class, TextKind::Ascii, entropy)
    }

    fn histogram(&self, block: &[u8]) -> Histogram {
        let mut h = Histogram::default();
        if self.sample_every == 1 || block.len() <= WINDOW * self.sample_every {
            h.add(block);
        } else {
            for w in block.chunks(WINDOW).step_by(self.sample_every) {
                h.add(w);
            }
        }
        h
    }
}

/// True when every byte equals `value`; compares 32 bytes per step.
fn is_uniform(block: &[u8], value: u8) -> bool {
    let pattern = u64::from_ne_bytes([value; 8]);
    let (words, rest) = block.as_chunks::<32>();
    for w in words {
        let diff = w.as_chunks::<8>().0.iter().fold(0u64, |acc, lane| acc | (u64::from_ne_bytes(*lane) ^ pattern));
        if diff != 0 {
            return false;
        }
    }
    rest.iter().all(|b| *b == value)
}

/// Byte counts split by position modulo 4 (even positions = tables 0 and 2).
struct Histogram {
    tables: [[u32; 256]; 4],
    total: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self { tables: [[0; 256]; 4], total: 0 }
    }
}

impl Histogram {
    /// Windows always start at even offsets (block and window sizes are even), so the parity
    /// split stays aligned to the block.
    fn add(&mut self, data: &[u8]) {
        let [t0, t1, t2, t3] = &mut self.tables;
        let (quads, rest) = data.as_chunks::<4>();
        for q in quads {
            t0[usize::from(q[0])] += 1;
            t1[usize::from(q[1])] += 1;
            t2[usize::from(q[2])] += 1;
            t3[usize::from(q[3])] += 1;
        }
        for (i, b) in rest.iter().enumerate() {
            self.tables[i][usize::from(*b)] += 1;
        }
        self.total += data.len() as u64;
    }

    fn count(&self, b: u8) -> u64 {
        self.tables.iter().map(|t| u64::from(t[usize::from(b)])).sum()
    }

    fn sum(&self, bytes: impl Iterator<Item = u8>) -> u64 {
        bytes.map(|b| self.count(b)).sum()
    }

    fn entropy(&self) -> f32 {
        let n = self.total as f64;
        if n == 0.0 {
            return 0.0;
        }
        let e: f64 = (0..=255u8)
            .map(|b| self.count(b) as f64)
            .filter(|c| *c > 0.0)
            .map(|c| {
                let p = c / n;
                -p * p.log2()
            })
            .sum();
        e as f32
    }

    /// Encoding when the sample reads as text; `None` otherwise.
    fn text_kind(&self) -> Option<TextKind> {
        let n = self.total;
        let controls = self.sum((0x01..=0x08).chain([0x0B, 0x0C]).chain(0x0E..=0x1F).chain([0x7F]));
        let zeros = self.count(0);
        let high = self.sum(0x80..=0xFF);
        let utf16 = zeros * 3 >= n && {
            let even = u64::from(self.tables[0][0]) + u64::from(self.tables[2][0]);
            let odd = zeros - even;
            even.max(odd) * 10 >= zeros * 9
        };
        let bad = controls + if utf16 { 0 } else { zeros };
        if 1.0 - (bad as f32 / n as f32) < TEXT_RATIO {
            return None;
        }
        if utf16 {
            return Some(TextKind::Utf16);
        }
        if high == 0 {
            return Some(TextKind::Ascii);
        }
        let utf8 = self.looks_utf8(high);
        // Single-byte text keeps a fair share of ASCII (spaces, digits, punctuation).
        if !utf8 && high * 10 > n * 9 {
            return None;
        }
        Some(if utf8 { TextKind::Utf8 } else { TextKind::SingleByte8 })
    }

    /// UTF-8 by byte statistics: (almost) no bytes that never occur in UTF-8, and at least one
    /// continuation byte per lead byte.
    fn looks_utf8(&self, high: u64) -> bool {
        let invalid = self.sum([0xC0, 0xC1].into_iter().chain(0xF5..=0xFF));
        let leads = self.sum(0xC2..=0xF4);
        let continuation = high - leads - invalid;
        invalid * 1000 <= high && leads > 0 && continuation >= leads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    fn check_classes(c: Classifier) {
        let block = 64 * 1024;
        let class = |data: &[u8]| c.classify(data);
        assert_eq!(class(&vec![0u8; block]).class(), BlockClass::Zero);
        assert_eq!(class(&vec![0xFFu8; block]).class(), BlockClass::Fill);
        let mut almost_zero = vec![0u8; block];
        almost_zero[block - 1] = 1;
        assert_ne!(class(&almost_zero).class(), BlockClass::Zero, "a single non-zero byte is content");
        let ascii = b"The quick brown fox jumps over the lazy dog. ".repeat(block / 45 + 1);
        let r = class(&ascii[..block]);
        assert_eq!((r.class(), r.text_kind()), (BlockClass::Text, Some(TextKind::Ascii)));
        let utf16: Vec<u8> = ascii[..block / 2].iter().flat_map(|b| [*b, 0]).collect();
        assert_eq!(class(&utf16).text_kind(), Some(TextKind::Utf16));
        let cyrillic = "\u{0421}\u{044a}\u{0435}\u{0448}\u{044c} \u{0436}\u{0435} \u{0435}\u{0449}\u{0451}. ".repeat(4000);
        assert_eq!(class(&cyrillic.as_bytes()[..block]).text_kind(), Some(TextKind::Utf8));
        // An 8-bit code page: letters in 0xC0..=0xFF with ASCII spaces between words.
        let cp1251: Vec<u8> = (0..block).map(|i| if i % 7 == 6 { b' ' } else { 0xC0 + (i % 64) as u8 }).collect();
        assert_eq!(class(&cp1251).text_kind(), Some(TextKind::SingleByte8));
        let r = class(&noise(block));
        assert_eq!(r.class(), BlockClass::Random);
        assert_eq!(r.entropy_bucket(), 15, "about 8 bits per byte");
        let mut structured = noise(block);
        for (i, b) in structured.iter_mut().enumerate() {
            if i % 4 != 0 {
                *b = (i % 8) as u8;
            }
        }
        assert_eq!(class(&structured).class(), BlockClass::Binary);
    }

    #[test]
    fn classifies_full_and_sampled() {
        check_classes(Classifier::default());
        check_classes(Classifier::sampled(4));
    }

    #[test]
    fn tolerates_short_and_odd_blocks() {
        let c = Classifier::default();
        assert_eq!(c.classify(&[]).class(), BlockClass::Zero);
        assert_eq!(c.classify(&[0u8; 7]).class(), BlockClass::Zero);
        assert_eq!(c.classify(b"hi there").class(), BlockClass::Text);
        let _ = c.classify(&[1, 2, 3]);
    }
}
