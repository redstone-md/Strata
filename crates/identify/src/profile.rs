//! Per-block content profile: which parts of a buffer are zero-filled (typical bad-sector
//! damage in our sources), text, structured binary or compressed/encrypted.

use serde::{Deserialize, Serialize};
use strata_kernel::ByteRange;
use strata_kernel::bytes::entropy;

pub const BLOCK: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockClass {
    /// All zero bytes.
    Zero,
    /// One byte value repeated (0xFF erase pattern, padding).
    Fill,
    /// Mostly printable characters.
    Text,
    /// Entropy close to 8 bits/byte: compressed or encrypted.
    Random,
    /// Anything else: tables, code, headers.
    Binary,
}

impl BlockClass {
    pub fn classify(block: &[u8]) -> Self {
        let Some(first) = block.first() else { return BlockClass::Zero };
        if block.iter().all(|b| b == first) {
            return if *first == 0 { BlockClass::Zero } else { BlockClass::Fill };
        }
        if text_ratio(block) >= 0.97 {
            return BlockClass::Text;
        }
        // Small trailing blocks cannot reach high entropy; scale the threshold.
        let max = (block.len() as f32).log2().min(8.0);
        if entropy(block) >= max * 0.93 {
            BlockClass::Random
        } else {
            BlockClass::Binary
        }
    }
}

/// Printable ASCII, whitespace, UTF-8 / CP1251 high bytes and UTF-16 zero padding all count.
pub fn text_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let is_control = |b: u8| matches!(b, 0x01..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F);
    let controls = data.iter().filter(|b| is_control(**b)).count();
    let zeros = data.iter().filter(|b| **b == 0).count();
    let high = data.iter().filter(|b| **b >= 0x80).count();
    // UTF-16 text: zeros concentrated on one byte parity.
    let utf16 = if zeros * 3 >= data.len() {
        let odd = data.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
        let even = zeros - odd;
        odd.max(even) * 10 >= zeros * 9
    } else {
        false
    };
    let bad = controls + if utf16 { 0 } else { zeros };
    // Single-byte text still has a fair share of ASCII; UTF-8 may not (Cyrillic, CJK).
    if !utf16 && high * 10 > data.len() * 9 && !is_utf8(data) {
        return 0.0;
    }
    1.0 - bad as f32 / data.len() as f32
}

/// Valid UTF-8, tolerating a sequence cut at either end (block boundaries).
pub fn is_utf8(data: &[u8]) -> bool {
    let skip = data.iter().take(3).take_while(|b| (0x80..0xC0).contains(*b)).count();
    match std::str::from_utf8(&data[skip..]) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

/// Summary of a buffer's blocks.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BlockProfile {
    pub block_size: usize,
    pub blocks: usize,
    pub zero: usize,
    pub fill: usize,
    pub text: usize,
    pub random: usize,
    pub binary: usize,
    /// Coalesced zero-filled ranges (candidates for unreadable sectors).
    pub zero_ranges: Vec<ByteRange>,
}

impl BlockProfile {
    pub fn of(data: &[u8]) -> Self {
        let mut p = BlockProfile { block_size: BLOCK, ..Default::default() };
        let mut zeros = Vec::new();
        for (i, block) in data.chunks(BLOCK).enumerate() {
            p.blocks += 1;
            match BlockClass::classify(block) {
                BlockClass::Zero => {
                    p.zero += 1;
                    zeros.push(ByteRange::new((i * BLOCK) as u64, block.len() as u64));
                }
                BlockClass::Fill => p.fill += 1,
                BlockClass::Text => p.text += 1,
                BlockClass::Random => p.random += 1,
                BlockClass::Binary => p.binary += 1,
            }
        }
        p.zero_ranges = ByteRange::coalesce(zeros);
        p
    }

    fn frac(&self, n: usize) -> f32 {
        if self.blocks == 0 { 0.0 } else { n as f32 / self.blocks as f32 }
    }

    pub fn zero_fraction(&self) -> f32 {
        self.frac(self.zero)
    }

    pub fn random_fraction(&self) -> f32 {
        self.frac(self.random)
    }

    pub fn text_fraction(&self) -> f32 {
        self.frac(self.text)
    }

    /// Fraction of blocks that carry content (not zero-filled).
    pub fn intact_fraction(&self) -> f32 {
        if self.blocks == 0 { 0.0 } else { 1.0 - self.zero_fraction() }
    }

    /// Fraction of non-zero blocks that look random.
    pub fn random_share_of_content(&self) -> f32 {
        let content = self.blocks.saturating_sub(self.zero + self.fill);
        if content == 0 { 0.0 } else { self.random as f32 / content as f32 }
    }

    /// Fraction of non-zero blocks that look like text.
    pub fn text_share_of_content(&self) -> f32 {
        let content = self.blocks.saturating_sub(self.zero + self.fill);
        if content == 0 { 0.0 } else { self.text as f32 / content as f32 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_blocks() {
        assert_eq!(BlockClass::classify(&[0u8; 4096]), BlockClass::Zero);
        assert_eq!(BlockClass::classify(&[0xFFu8; 4096]), BlockClass::Fill);
        assert_eq!(BlockClass::classify(&b"hello world. ".repeat(300)), BlockClass::Text);
        let mut x = 0x1234_5678u32;
        let rnd: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 24) as u8
            })
            .collect();
        assert_eq!(BlockClass::classify(&rnd), BlockClass::Random);
    }

    #[test]
    fn zero_ranges_coalesce() {
        let mut data = vec![1u8; BLOCK * 4];
        data[BLOCK..BLOCK * 3].fill(0);
        let p = BlockProfile::of(&data);
        assert_eq!(p.zero, 2);
        assert_eq!(p.zero_ranges, vec![ByteRange::new(BLOCK as u64, (BLOCK * 2) as u64)]);
    }
}
