//! LZNT1 decompression (NTFS compressed attributes) and unit-wise reading of compressed files.

use crate::{FileEntry};
use strata_kernel::Result;
use strata_kernel::bytes::u16_le;
use strata_source::BlockSource;

const CHUNK: usize = 4096;

/// Decompress an LZNT1 buffer into at most `limit` bytes. Damaged chunks end decoding early;
/// what was produced so far is returned.
pub(super) fn decompress(input: &[u8], limit: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(limit);
    let mut pos = 0usize;
    while out.len() < limit {
        let Some(header) = u16_le(input, pos) else { break };
        if header == 0 {
            break;
        }
        let len = usize::from(header & 0x0FFF) + 1;
        let Some(data) = input.get(pos + 2..pos + 2 + len) else { break };
        pos += 2 + len;
        let chunk_start = out.len();
        if header & 0x8000 == 0 {
            out.extend_from_slice(data);
        } else if !decode_chunk(data, &mut out, chunk_start) {
            break;
        }
        // Every chunk but the last decompresses to exactly 4 KiB.
        if out.len() - chunk_start < CHUNK && pos < input.len() && u16_le(input, pos).is_some_and(|h| h != 0) {
            out.resize(chunk_start + CHUNK, 0);
        }
    }
    out.truncate(limit);
    out
}

fn decode_chunk(data: &[u8], out: &mut Vec<u8>, chunk_start: usize) -> bool {
    let mut i = 0usize;
    while i < data.len() {
        let flags = data[i];
        i += 1;
        for bit in 0..8 {
            if i >= data.len() {
                return true;
            }
            if flags & (1 << bit) == 0 {
                out.push(data[i]);
                i += 1;
                continue;
            }
            let Some(token) = u16_le(data, i) else { return false };
            i += 2;
            let pos = out.len() - chunk_start;
            if pos == 0 {
                return false;
            }
            let mut lg = 0u32;
            let mut p = pos - 1;
            while p >= 0x10 {
                p >>= 1;
                lg += 1;
            }
            let back = usize::from(token >> (12 - lg)) + 1;
            let len = usize::from(token & (0x0FFF >> lg)) + 3;
            if back > pos || out.len() - chunk_start + len > CHUNK {
                return false;
            }
            let from = out.len() - back;
            for k in 0..len {
                let b = out[from + k];
                out.push(b);
            }
        }
    }
    true
}

/// Reads a compressed file unit by unit: fully allocated units are stored raw, partly
/// allocated ones hold LZNT1 data, unallocated ones are zeros.
pub(super) struct CompressedReader<'a> {
    source: &'a dyn BlockSource,
    entry: &'a FileEntry,
    unit: u64,
}

impl<'a> CompressedReader<'a> {
    pub(super) fn new(source: &'a dyn BlockSource, entry: &'a FileEntry, unit: u64) -> Self {
        Self { source, entry, unit: unit.max(1) }
    }

    pub(super) fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.entry.size {
            return Ok(0);
        }
        let want = buf.len().min((self.entry.size - offset) as usize);
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let unit_index = pos / self.unit;
            let data = self.unit_bytes(unit_index)?;
            let in_unit = (pos - unit_index * self.unit) as usize;
            let n = (want - done).min(self.unit as usize - in_unit);
            let dst = &mut buf[done..done + n];
            dst.fill(0);
            if let Some(src) = data.get(in_unit..) {
                let m = src.len().min(n);
                dst[..m].copy_from_slice(&src[..m]);
            }
            done += n;
        }
        Ok(want)
    }

    fn unit_bytes(&self, index: u64) -> Result<Vec<u8>> {
        let start = index * self.unit;
        let end = start + self.unit;
        let mut stored = Vec::new();
        for ext in &self.entry.extents {
            let lo = start.max(ext.file_offset);
            let hi = end.min(ext.file_offset + ext.len);
            let (true, Some(vol)) = (lo < hi, ext.volume_offset) else { continue };
            let mut part = vec![0u8; (hi - lo) as usize];
            self.source.read_at(vol + (lo - ext.file_offset), &mut part)?;
            stored.extend_from_slice(&part);
        }
        Ok(match stored.len() as u64 {
            0 => Vec::new(),
            n if n >= self.unit => stored,
            _ => decompress(&stored, self.unit as usize),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompresses_backreferences() {
        // "abcabcabcabc": literals a b c, then a back-reference of length 9 at distance 3.
        // pos = 3 -> lg = 0 -> token = ((3 - 1) << 12) | (9 - 3).
        let token: u16 = (2 << 12) | 6;
        let mut body = vec![0b0000_1000, b'a', b'b', b'c'];
        body.extend_from_slice(&token.to_le_bytes());
        let header = 0x8000u16 | 0x3000 | (body.len() as u16 - 1);
        let mut input = header.to_le_bytes().to_vec();
        input.extend_from_slice(&body);
        assert_eq!(decompress(&input, 4096), b"abcabcabcabc");
    }

    #[test]
    fn garbage_never_panics() {
        for seed in 1..50 {
            let noise = crate::testutil::noise(5000, seed);
            let out = decompress(&noise, 65536);
            assert!(out.len() <= 65536);
        }
    }
}
