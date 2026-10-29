//! Section descriptors: the linked list every EWF v1 segment file is made of.
//!
//! Descriptor (76 bytes): `type[16]` (ASCII, NUL padded) | `u64 next` (absolute offset in the
//! segment) | `u64 size` (descriptor included) | 40 bytes padding | `u32 adler32` of bytes 0..72.

use crate::file_io::read_full_at;
use std::fs::File;
use strata_kernel::bytes::{array, u64_le};

/// Signature (8) + fields start (1) + segment number (2) + fields end (2).
pub(super) const FILE_HEADER_LEN: u64 = 13;
const DESCRIPTOR_LEN: u64 = 76;
const MAX_SECTIONS: usize = 1 << 20;

/// Adler-32 as EWF uses it for descriptors, tables and uncompressed chunks.
pub(super) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    // 5552 is the largest block for which the sums cannot overflow a u32.
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(5552) {
        for &x in block {
            a += u32::from(x);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[derive(Debug, Clone)]
pub(super) struct Section {
    kind: String,
    start: u64,
    size: u64,
}

impl Section {
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    fn data_start(&self) -> u64 {
        self.start + DESCRIPTOR_LEN
    }

    /// Whether `offset` falls inside this section's payload.
    pub fn holds(&self, offset: u64) -> bool {
        offset >= self.data_start() && offset < self.end()
    }

    /// Payload bytes, at most `cap`, truncated at end of file. `None` only on I/O failure.
    pub fn read_data(&self, file: &File, file_len: u64, cap: u64) -> Option<Vec<u8>> {
        let len = self.size.saturating_sub(DESCRIPTOR_LEN).min(cap).min(file_len.saturating_sub(self.data_start()));
        let mut buf = vec![0u8; len as usize];
        let n = read_full_at(file, self.data_start(), &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    fn parse(raw: &[u8; DESCRIPTOR_LEN as usize], start: u64, file_len: u64) -> Option<(Self, u64)> {
        let name = array::<16>(raw, 0)?;
        let kind: String = name.iter().take_while(|b| **b != 0).map(|b| char::from(*b).to_ascii_lowercase()).collect();
        let next = u64_le(raw, 16)?;
        let declared = u64_le(raw, 24)?;
        let fits = |end: u64| end > start && end <= file_len;
        // `done`/`next` carry size 0; a damaged size falls back to the next pointer.
        let size = match start.checked_add(declared) {
            Some(end) if declared >= DESCRIPTOR_LEN && fits(end) => declared,
            _ if fits(next) => next - start,
            _ => DESCRIPTOR_LEN,
        };
        let next = if fits(next) { next } else { start + size };
        Some((Self { kind, start, size }, next))
    }
}

/// Follow the section chain of one segment file until `done`/`next`, a loop or a dead link.
pub(super) fn walk(file: &File, file_len: u64) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut pos = FILE_HEADER_LEN;
    let mut raw = [0u8; DESCRIPTOR_LEN as usize];
    while sections.len() < MAX_SECTIONS && pos.saturating_add(DESCRIPTOR_LEN) <= file_len {
        if !matches!(read_full_at(file, pos, &mut raw), Ok(n) if n == raw.len()) {
            break;
        }
        let Some((section, next)) = Section::parse(&raw, pos, file_len) else { break };
        let last = matches!(section.kind(), "done" | "next");
        sections.push(section);
        if last || next <= pos {
            break;
        }
        pos = next;
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::adler32;

    #[test]
    fn adler32_reference_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let big = vec![0xFFu8; 100_000];
        let (a, b) = big.iter().fold((1u64, 0u64), |(a, b), x| {
            let a = (a + u64::from(*x)) % 65_521;
            (a, (b + a) % 65_521)
        });
        assert_eq!(adler32(&big), ((b << 16) | a) as u32);
    }
}
