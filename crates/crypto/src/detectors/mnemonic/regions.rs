//! Fast prefilter: a written-down phrase has a word separator every few bytes. Separators
//! are found with SIMD `memchr3`; only regions dense in separators reach the tokenizer.
//! Random/binary data has ~3/256 candidate bytes and almost never qualifies.

use memchr::memchr3_iter;

/// Separators needed inside one window for a region to qualify.
const MIN_SEPARATORS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct RegionFinder {
    /// Max distance (bytes) spanned by `MIN_SEPARATORS` consecutive separators.
    window: usize,
    /// Bytes added on each side of a dense region (covers the first/last word).
    margin: usize,
    utf16: bool,
}

impl RegionFinder {
    pub const UTF8: RegionFinder = RegionFinder { window: 320, margin: 96, utf16: false };
    pub const UTF16LE: RegionFinder = RegionFinder { window: 640, margin: 192, utf16: true };

    /// Is the candidate byte at `i` really a separator in this encoding?
    #[inline]
    fn separator_at(&self, chunk: &[u8], i: usize) -> bool {
        let b = chunk[i];
        if !self.utf16 {
            // ' ', '\n', or the lead byte of U+3000 (E3 80 80).
            return b != 0xe3 || chunk.get(i + 1..i + 3) == Some(&[0x80, 0x80]);
        }
        match b {
            // U+0020 / U+000A little-endian.
            b' ' | b'\n' => chunk.get(i + 1) == Some(&0),
            // U+3000 little-endian is `00 30`: the 0x30 is the high byte.
            _ => i > 0 && chunk[i - 1] == 0,
        }
    }

    /// Merged `[start, end)` byte regions worth tokenizing.
    pub fn regions(&self, chunk: &[u8]) -> Vec<(usize, usize)> {
        let (a, b, c) = if self.utf16 { (b' ', b'\n', 0x30) } else { (b' ', b'\n', 0xe3) };
        let mut ring = [0usize; MIN_SEPARATORS];
        let mut count = 0usize;
        let mut out: Vec<(usize, usize)> = Vec::new();
        for i in memchr3_iter(a, b, c, chunk) {
            if !self.separator_at(chunk, i) {
                continue;
            }
            let oldest = ring[count % MIN_SEPARATORS];
            ring[count % MIN_SEPARATORS] = i;
            count += 1;
            if count < MIN_SEPARATORS || i - oldest > self.window {
                continue;
            }
            let start = oldest.saturating_sub(self.margin);
            let end = (i + self.margin).min(chunk.len());
            match out.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => out.push((start, end)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_text_only() {
        let mut data = vec![0x41u8; 2000];
        data.extend(b"one two three four five six seven eight nine ten");
        data.extend(vec![0x41u8; 2000]);
        let r = RegionFinder::UTF8.regions(&data);
        assert_eq!(r.len(), 1);
        assert!(r[0].0 <= 2000 && r[0].1 >= 2048);
        assert!(RegionFinder::UTF8.regions(&[b' '; 3]).is_empty());
        let wide: Vec<u8> = "a b c d e f g h i j".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(RegionFinder::UTF16LE.regions(&wide).len(), 1);
    }
}
