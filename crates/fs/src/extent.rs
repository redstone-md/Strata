use crate::FileEntry;
use serde::{Deserialize, Serialize};
use strata_kernel::Result;
use strata_source::BlockSource;

/// A run of file content: `len` bytes of the file starting at `file_offset` are stored at
/// `volume_offset`, or are sparse (zeros) when `volume_offset` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub file_offset: u64,
    pub volume_offset: Option<u64>,
    pub len: u64,
}

/// Reads a [`FileEntry`]'s content from its volume. Shared by all filesystems.
pub struct ExtentReader<'a> {
    source: &'a dyn BlockSource,
    entry: &'a FileEntry,
}

impl<'a> ExtentReader<'a> {
    pub fn new(source: &'a dyn BlockSource, entry: &'a FileEntry) -> Self {
        Self { source, entry }
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.entry.size {
            return Ok(0);
        }
        let want = buf.len().min((self.entry.size - offset) as usize);
        let buf = &mut buf[..want];
        if let Some(data) = &self.entry.resident {
            let start = (offset as usize).min(data.len());
            let n = want.min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            buf[n..].fill(0);
            return Ok(want);
        }
        buf.fill(0);
        for ext in &self.entry.extents {
            let ext_end = ext.file_offset + ext.len;
            let lo = offset.max(ext.file_offset);
            let hi = (offset + want as u64).min(ext_end);
            if lo >= hi {
                continue;
            }
            if let Some(vol) = ext.volume_offset {
                let dst = &mut buf[(lo - offset) as usize..(hi - offset) as usize];
                self.source.read_at(vol + (lo - ext.file_offset), dst)?;
            }
        }
        Ok(want)
    }

    pub fn read_all(&self, limit: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; (self.entry.size as usize).min(limit)];
        let n = self.read(0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}
