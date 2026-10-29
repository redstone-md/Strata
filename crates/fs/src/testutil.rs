//! In-memory evidence for parser tests.

use std::sync::Arc;
use strata_kernel::{ByteRange, Result};
use strata_source::{BlockSource, SourceInfo, SourceKind};

pub(crate) struct MemSource(Vec<u8>);

impl BlockSource for MemSource {
    fn info(&self) -> SourceInfo {
        SourceInfo { kind: SourceKind::RawImage, label: "mem".into(), location: "mem".into(), len: self.len(), sector_size: 512 }
    }

    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(self.0.len());
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }

    fn damage(&self) -> Vec<ByteRange> {
        Vec::new()
    }
}

pub(crate) fn mem(bytes: Vec<u8>) -> Arc<dyn BlockSource> {
    Arc::new(MemSource(bytes))
}

/// Deterministic pseudo-random bytes (xorshift) for fuzz-style tests.
pub(crate) fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}
