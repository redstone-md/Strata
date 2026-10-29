//! Disk ranges derived from a parsed layout: free space (unallocated clusters of every parsed
//! filesystem plus disk space no parsed volume covers) and the content of deleted files.

use crate::EvidenceLayout;
use strata_fs::FileSystem;
use strata_kernel::ByteRange;
use strata_volume::Volume;

impl EvidenceLayout {
    /// Unallocated space of every parsed filesystem plus disk space outside parsed volumes
    /// (absolute, sorted, coalesced).
    pub fn free_space(&self, disk_len: u64) -> Vec<ByteRange> {
        let mut ranges: Vec<ByteRange> =
            self.filesystems().flat_map(|(vol, fs)| fs.unallocated().into_iter().map(move |r| r.shifted(vol.range.start()))).collect();
        let mut covered: Vec<ByteRange> = self.filesystems().map(|(v, _)| v.range).collect();
        covered.sort();
        let mut cursor = 0;
        for c in covered.iter().chain(std::iter::once(&ByteRange::new(disk_len, 0))) {
            if c.start() > cursor {
                ranges.push(ByteRange::from_bounds(cursor, c.start()));
            }
            cursor = cursor.max(c.end());
        }
        ByteRange::coalesce(ranges)
    }

    /// Content of deleted and orphaned files (extents and resident data), absolute.
    pub fn deleted_content(&self) -> Vec<ByteRange> {
        let ranges = self.filesystems().flat_map(|(vol, fs)| deleted_in(vol, fs)).collect();
        ByteRange::coalesce(ranges)
    }

    /// The parsed filesystem of volume `index`, if it parsed.
    pub fn filesystem(&self, index: u32) -> Option<(&Volume, &dyn FileSystem)> {
        self.filesystems().find(|(v, _)| v.index == index)
    }
}

fn deleted_in<'a>(vol: &'a Volume, fs: &'a dyn FileSystem) -> impl Iterator<Item = ByteRange> + 'a {
    let base = vol.range.start();
    fs.entries().iter().filter(|e| e.is_deleted() && !e.is_dir).flat_map(move |e| {
        let resident = e.resident_offset.zip(e.resident.as_ref()).map(|(at, d)| ByteRange::new(base + at, d.len() as u64));
        e.extents.iter().filter_map(move |x| x.volume_offset.map(|v| ByteRange::new(base + v, x.len))).chain(resident)
    })
}
