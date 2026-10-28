use serde::{Deserialize, Serialize};
use strata_kernel::{ByteRange, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    RawImage,
    RStudioImage,
    PhysicalDrive,
    Slice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub kind: SourceKind,
    pub label: String,
    pub location: String,
    pub len: u64,
    pub sector_size: u32,
}

/// Random-access, read-only view of evidence bytes.
///
/// Implementations must be thread-safe so the scan engine can read in parallel.
pub trait BlockSource: Send + Sync {
    fn info(&self) -> SourceInfo;

    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` from `offset`. Returns bytes produced (short only at end of source).
    /// Unreadable areas are zero-filled and recorded in [`BlockSource::damage`].
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Ranges known to be unreadable or absent (sorted, coalesced).
    fn damage(&self) -> Vec<ByteRange>;

    /// Convenience: read exactly `len` bytes (truncated at end of source).
    fn read_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(offset, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}
