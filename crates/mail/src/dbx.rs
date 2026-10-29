//! Outlook Express `.dbx` folders (best effort): message bodies live in 0x200-byte chunks with
//! a 16-byte header (self offset, body size, data length, next chunk). Chains are rebuilt from
//! every self-consistent chunk header, so deleted-but-unwiped messages are found too.

use std::collections::{HashMap, HashSet};
use strata_kernel::bytes::u32_le;

pub const DBX_MAGIC: [u8; 4] = [0xCF, 0xAD, 0x12, 0xFE];
const CHUNK: usize = 0x200;
const HEADER: usize = 16;
const MAX_CHAIN: usize = 1 << 17;

/// The message chains of one folder file.
pub struct Dbx {
    /// Chunk offset → (data length, next chunk).
    chunks: HashMap<usize, (usize, usize)>,
}

impl Dbx {
    pub fn is_dbx(data: &[u8]) -> bool {
        data.starts_with(&DBX_MAGIC)
    }

    /// Index every chunk header of `data` (the whole file, signature or not).
    pub fn scan(data: &[u8]) -> Self {
        let mut chunks = HashMap::new();
        let mut p = 0;
        while p + HEADER <= data.len() {
            if let Some((len, next)) = chunk_header(&data[p..p + HEADER], p) {
                chunks.insert(p, (len, next));
            }
            p += 4;
        }
        Self { chunks }
    }

    /// Offsets of the first chunk of every chain, in file order.
    pub fn heads(&self) -> Vec<usize> {
        let referenced: HashSet<usize> = self.chunks.values().map(|c| c.1).collect();
        let mut heads: Vec<usize> = self.chunks.keys().copied().filter(|o| !referenced.contains(o)).collect();
        heads.sort_unstable();
        heads
    }

    /// The message bytes of the chain starting at `head`.
    pub fn message(&self, data: &[u8], head: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = head;
        let mut seen = HashSet::new();
        while let Some(&(len, next)) = self.chunks.get(&cur) {
            if !seen.insert(cur) || seen.len() > MAX_CHAIN {
                break;
            }
            if let Some(b) = data.get(cur + HEADER..cur + HEADER + len) {
                out.extend_from_slice(b);
            }
            if next == 0 {
                break;
            }
            cur = next;
        }
        out
    }

    /// The message bytes of the chain at `head`, following chunk headers through `read`
    /// (re-extraction without reading the whole folder file). Stops at the first chunk that
    /// does not check out.
    pub fn read_message(mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>, head: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = head as usize;
        let mut seen = HashSet::new();
        while seen.insert(cur) && seen.len() <= MAX_CHAIN {
            let Some(chunk) = read(cur as u64, HEADER + CHUNK) else { break };
            let Some((len, next)) = chunk.get(..HEADER).and_then(|h| chunk_header(h, cur)) else { break };
            out.extend_from_slice(chunk.get(HEADER..HEADER + len).unwrap_or_default());
            if next == 0 {
                break;
            }
            cur = next;
        }
        out
    }
}

/// `(data length, next)` when the 16 bytes at file offset `at` are a chunk header.
fn chunk_header(h: &[u8], at: usize) -> Option<(usize, usize)> {
    if u32_le(h, 0)? as usize != at || u32_le(h, 4)? as usize != CHUNK {
        return None;
    }
    let len = u32_le(h, 8)? as usize;
    (len <= CHUNK).then(|| (len, u32_le(h, 12).unwrap_or(0) as usize))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A folder file holding `messages` as chunk chains.
    pub(crate) fn build(messages: &[&[u8]]) -> Vec<u8> {
        let mut d = vec![0u8; 0x24BC];
        d[..4].copy_from_slice(&DBX_MAGIC);
        for m in messages {
            let parts: Vec<&[u8]> = m.chunks(CHUNK).collect();
            let base = d.len();
            for (i, part) in parts.iter().enumerate() {
                let off = base + i * (CHUNK + HEADER);
                let next = if i + 1 < parts.len() { off + CHUNK + HEADER } else { 0 };
                let mut c = vec![0u8; CHUNK + HEADER];
                c[0..4].copy_from_slice(&(off as u32).to_le_bytes());
                c[4..8].copy_from_slice(&(CHUNK as u32).to_le_bytes());
                c[8..12].copy_from_slice(&(part.len() as u32).to_le_bytes());
                c[12..16].copy_from_slice(&(next as u32).to_le_bytes());
                c[16..16 + part.len()].copy_from_slice(part);
                d.extend_from_slice(&c);
            }
        }
        d
    }

    #[test]
    fn rebuilds_chains_both_ways() {
        let long = format!("From: a@example.com\r\nSubject: {}\r\n\r\nhi", "x".repeat(700));
        let data = build(&[long.as_bytes(), b"From: b@example.com\r\nSubject: two\r\n\r\n"]);
        assert!(Dbx::is_dbx(&data));
        let dbx = Dbx::scan(&data);
        let heads = dbx.heads();
        assert_eq!(heads.len(), 2);
        assert_eq!(dbx.message(&data, heads[0]), long.as_bytes());
        let read = |at: u64, len: usize| data.get(at as usize..(at as usize + len).min(data.len())).map(<[u8]>::to_vec);
        assert_eq!(Dbx::read_message(read, heads[0] as u64), long.as_bytes());
        assert!(Dbx::read_message(read, 3).is_empty());
        for cut in (0..data.len()).step_by(101) {
            let part = Dbx::scan(&data[..cut]);
            for h in part.heads() {
                part.message(&data[..cut], h);
            }
        }
    }
}
