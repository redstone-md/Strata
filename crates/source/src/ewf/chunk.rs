//! Chunk payloads: zlib-compressed, or raw with a trailing Adler-32, plus a small shared LRU.

use super::section::adler32;
use crate::file_io::read_full_at;
use flate2::read::ZlibDecoder;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use strata_kernel::bytes::u32_le;

/// Where one chunk's stored bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ChunkRef {
    pub segment: usize,
    pub offset: u64,
    pub stored: u64,
    pub compressed: bool,
}

/// Inflate a zlib stream, producing at most `limit` bytes. `None` on a corrupt stream.
pub(super) fn inflate(raw: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(limit.min(1 << 20));
    ZlibDecoder::new(raw).take(limit as u64).read_to_end(&mut out).ok()?;
    Some(out)
}

/// Decode chunk `chunk` into exactly `expected` bytes, or `None` when it cannot be trusted
/// (short read, corrupt stream, checksum mismatch, too little data).
pub(super) fn decode(file: &File, chunk: &ChunkRef, chunk_size: usize, expected: usize) -> Option<Vec<u8>> {
    let limit = if chunk.compressed { chunk_size * 2 + 1024 } else { chunk_size + 4 };
    let len = chunk.stored.min(limit as u64) as usize;
    if len == 0 {
        return None;
    }
    let mut raw = vec![0u8; len];
    let n = read_full_at(file, chunk.offset, &mut raw).ok()?;
    raw.truncate(n);
    let mut data = if chunk.compressed { inflate(&raw, chunk_size)? } else { verify_raw(raw, chunk_size)? };
    if data.len() < expected {
        return None;
    }
    data.truncate(expected);
    Some(data)
}

/// Raw chunks carry an Adler-32 after the data (EnCase); SMART images store bare data.
fn verify_raw(mut raw: Vec<u8>, chunk_size: usize) -> Option<Vec<u8>> {
    if let Some(split) = raw.len().checked_sub(4)
        && raw.get(..split).map(adler32) == u32_le(&raw, split)
    {
        raw.truncate(split);
        return Some(raw);
    }
    (raw.len() <= chunk_size).then_some(raw)
}

/// Thread-safe LRU of decoded chunks keyed by chunk index. Decoding happens outside the lock.
pub(super) struct ChunkCache {
    slots: Mutex<VecDeque<(u64, Arc<[u8]>)>>,
    capacity: usize,
}

impl ChunkCache {
    pub fn new(capacity: usize) -> Self {
        Self { slots: Mutex::new(VecDeque::with_capacity(capacity)), capacity: capacity.max(1) }
    }

    pub fn get(&self, index: u64) -> Option<Arc<[u8]>> {
        let mut slots = self.slots.lock();
        let at = slots.iter().position(|(i, _)| *i == index)?;
        let hit = slots.remove(at)?;
        let data = hit.1.clone();
        slots.push_front(hit);
        Some(data)
    }

    pub fn put(&self, index: u64, data: Arc<[u8]>) {
        let mut slots = self.slots.lock();
        if slots.iter().any(|(i, _)| *i == index) {
            return;
        }
        if slots.len() >= self.capacity {
            slots.pop_back();
        }
        slots.push_front((index, data));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_least_recent() {
        let cache = ChunkCache::new(2);
        cache.put(1, Arc::from(&b"a"[..]));
        cache.put(2, Arc::from(&b"b"[..]));
        assert!(cache.get(1).is_some());
        cache.put(3, Arc::from(&b"c"[..]));
        assert!(cache.get(2).is_none());
        assert_eq!(cache.get(1).as_deref(), Some(&b"a"[..]));
    }

    #[test]
    fn raw_chunk_checksum() {
        let mut raw = b"data".to_vec();
        raw.extend(adler32(b"data").to_le_bytes());
        assert_eq!(verify_raw(raw.clone(), 4).as_deref(), Some(&b"data"[..]));
        raw[0] ^= 1;
        assert_eq!(verify_raw(raw, 4), None);
        assert_eq!(verify_raw(b"bare".to_vec(), 4).as_deref(), Some(&b"bare"[..]));
        assert!(inflate(b"not zlib", 16).is_none());
    }
}
