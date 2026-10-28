use crate::{BlockSource, SourceInfo, SourceKind};
use std::sync::Arc;
use strata_kernel::{ByteRange, Result};

/// A window into another source, e.g. one partition of a disk.
pub struct SliceSource {
    parent: Arc<dyn BlockSource>,
    range: ByteRange,
    label: String,
}

impl SliceSource {
    pub fn new(parent: Arc<dyn BlockSource>, range: ByteRange, label: impl Into<String>) -> Self {
        let clamped = ByteRange::from_bounds(range.start().min(parent.len()), range.end().min(parent.len()));
        Self { parent, range: clamped, label: label.into() }
    }

    pub fn range(&self) -> ByteRange {
        self.range
    }

    pub fn parent(&self) -> &Arc<dyn BlockSource> {
        &self.parent
    }
}

impl BlockSource for SliceSource {
    fn info(&self) -> SourceInfo {
        let parent = self.parent.info();
        SourceInfo {
            kind: SourceKind::Slice,
            label: self.label.clone(),
            location: format!("{} @ {}", parent.location, self.range),
            len: self.range.len(),
            sector_size: parent.sector_size,
        }
    }

    fn len(&self) -> u64 {
        self.range.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.range.len() {
            return Ok(0);
        }
        let n = buf.len().min((self.range.len() - offset) as usize);
        self.parent.read_at(self.range.start() + offset, &mut buf[..n])
    }

    fn damage(&self) -> Vec<ByteRange> {
        self.parent
            .damage()
            .iter()
            .filter_map(|d| d.intersect(&self.range))
            .map(|d| ByteRange::new(d.start() - self.range.start(), d.len()))
            .collect()
    }
}
