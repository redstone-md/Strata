//! Cluster allocation bitmaps and extent lists, shared by every cluster-based filesystem.

use crate::Extent;
use strata_kernel::ByteRange;

/// One bit per cluster, set = in use. Index 0 is the first cluster the caller maps.
pub(crate) struct ClusterMap {
    bits: Vec<u64>,
    count: u64,
}

impl ClusterMap {
    pub(crate) fn new(count: u64) -> Self {
        Self { bits: vec![0; count.div_ceil(64) as usize], count }
    }

    /// Bitmap bytes, LSB first (NTFS `$Bitmap`). Missing bytes count as free.
    pub(crate) fn from_lsb_bytes(bytes: &[u8], count: u64) -> Self {
        let mut map = Self::new(count);
        for (w, word) in map.bits.iter_mut().enumerate() {
            let mut raw = [0u8; 8];
            if let Some(src) = bytes.get(w * 8..) {
                let n = src.len().min(8);
                raw[..n].copy_from_slice(&src[..n]);
            }
            *word = u64::from_le_bytes(raw);
        }
        map.clear_tail();
        map
    }

    fn clear_tail(&mut self) {
        let rem = self.count % 64;
        if let (true, Some(last)) = (rem != 0, self.bits.last_mut()) {
            *last &= (1u64 << rem) - 1;
        }
    }

    pub(crate) fn set_used(&mut self, index: u64) {
        if index < self.count {
            self.bits[(index / 64) as usize] |= 1 << (index % 64);
        }
    }

    pub(crate) fn set_used_range(&mut self, start: u64, len: u64) {
        let end = start.saturating_add(len).min(self.count);
        for i in start..end {
            self.set_used(i);
        }
    }

    pub(crate) fn is_used(&self, index: u64) -> bool {
        index < self.count && self.bits[(index / 64) as usize] & (1 << (index % 64)) != 0
    }

    pub(crate) fn any_used(&self, start: u64, len: u64) -> bool {
        (start..start.saturating_add(len).min(self.count)).any(|i| self.is_used(i))
    }

    /// Free clusters as byte ranges, cluster `i` living at `base + i * cluster_size`.
    pub(crate) fn free_ranges(&self, base: u64, cluster_size: u64) -> Vec<ByteRange> {
        let mut out = Vec::new();
        let mut run_start: Option<u64> = None;
        let mut i = 0;
        while i < self.count {
            let word = self.bits[(i / 64) as usize];
            let whole_word = i % 64 == 0 && i + 64 <= self.count && (word == 0 || word == u64::MAX);
            let used = if whole_word { word != 0 } else { self.is_used(i) };
            match (used, run_start) {
                (false, None) => run_start = Some(i),
                (true, Some(s)) => {
                    out.push(Self::bytes(s, i, base, cluster_size));
                    run_start = None;
                }
                _ => {}
            }
            i += if whole_word { 64 } else { 1 };
        }
        if let Some(s) = run_start {
            out.push(Self::bytes(s, self.count, base, cluster_size));
        }
        out
    }

    fn bytes(start: u64, end: u64, base: u64, cluster_size: u64) -> ByteRange {
        ByteRange::new(base.saturating_add(start.saturating_mul(cluster_size)), (end - start).saturating_mul(cluster_size))
    }
}

/// Builds a file's extent list run by run, merging physically contiguous runs.
#[derive(Default)]
pub(crate) struct ExtentList {
    extents: Vec<Extent>,
    end: u64,
}

impl ExtentList {
    /// Append `len` bytes at the current end of the file.
    pub(crate) fn push(&mut self, volume_offset: Option<u64>, len: u64) {
        if len == 0 {
            return;
        }
        if let Some(last) = self.extents.last_mut() {
            let contiguous = match (last.volume_offset, volume_offset) {
                (Some(a), Some(b)) => a.checked_add(last.len) == Some(b),
                (None, None) => true,
                _ => false,
            };
            if contiguous {
                last.len = last.len.saturating_add(len);
                self.end = self.end.saturating_add(len);
                return;
            }
        }
        self.extents.push(Extent { file_offset: self.end, volume_offset, len });
        self.end = self.end.saturating_add(len);
    }

    /// Place a run at `file_offset`. Gaps become sparse; runs overlapping what is already
    /// placed are rejected (returns `false`).
    pub(crate) fn push_at(&mut self, file_offset: u64, volume_offset: Option<u64>, len: u64) -> bool {
        if file_offset < self.end {
            return false;
        }
        self.push(None, file_offset - self.end);
        self.push(volume_offset, len);
        true
    }

    pub(crate) fn end(&self) -> u64 {
        self.end
    }

    /// Final extents: cut at `size`, and bytes past `initialized` (never written) made sparse.
    pub(crate) fn finish(self, size: u64, initialized: u64) -> Vec<Extent> {
        let mut out = ExtentList::default();
        for ext in self.extents {
            let end = ext.file_offset.saturating_add(ext.len).min(size);
            if ext.file_offset >= end {
                break;
            }
            let split = initialized.clamp(ext.file_offset, end);
            if split > ext.file_offset {
                out.push_at(ext.file_offset, ext.volume_offset, split - ext.file_offset);
            }
            if end > split {
                out.push_at(split, None, end - split);
            }
        }
        out.extents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_ranges_cover_word_boundaries() {
        let mut map = ClusterMap::new(200);
        map.set_used_range(0, 3);
        map.set_used_range(64, 64);
        map.set_used(199);
        let free = map.free_ranges(1000, 10);
        assert_eq!(free, vec![ByteRange::new(1030, 610), ByteRange::new(2280, 710)]);
        assert!(map.any_used(60, 10));
        assert!(!map.any_used(130, 60));
    }

    #[test]
    fn bitmap_bytes_ignore_tail_bits() {
        let map = ClusterMap::from_lsb_bytes(&[0b0000_0101, 0xFF], 10);
        assert!(map.is_used(0) && !map.is_used(1) && map.is_used(2) && map.is_used(9));
        assert!(!map.is_used(10));
        assert_eq!(map.free_ranges(0, 1).len(), 2);
    }

    #[test]
    fn extent_list_merges_and_trims() {
        let mut list = ExtentList::default();
        list.push(Some(100), 10);
        list.push(Some(110), 10);
        assert!(list.push_at(30, Some(500), 20));
        assert!(!list.push_at(10, Some(0), 1));
        let ext = list.finish(45, 40);
        assert_eq!(
            ext,
            vec![
                Extent { file_offset: 0, volume_offset: Some(100), len: 20 },
                Extent { file_offset: 20, volume_offset: None, len: 10 },
                Extent { file_offset: 30, volume_offset: Some(500), len: 10 },
                Extent { file_offset: 40, volume_offset: None, len: 5 },
            ]
        );
    }
}
