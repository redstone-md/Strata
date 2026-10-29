//! Block ownership for the disk index, from the parsed volumes and filesystems.

use strata_case::EvidenceLayout;
use strata_index::Ownership;
use strata_kernel::ByteRange;
use strata_volume::Volume;

/// Ownership spans of one evidence item: parsed volumes are allocated (live) space except
/// their unallocated ranges; unallocated space a deleted entry still points to is a deleted
/// file; disk space outside every volume is outside volumes. Volumes whose filesystem could
/// not be parsed stay unknown.
pub(crate) fn spans(layout: &EvidenceLayout, volumes: &[Volume], disk_len: u64) -> Vec<(ByteRange, Ownership)> {
    let mut out = Vec::new();
    for (vol, fs) in layout.filesystems() {
        out.push((vol.range, Ownership::LiveFile));
        let base = vol.range.start();
        let free = ByteRange::coalesce(fs.unallocated().into_iter().map(|r| r.shifted(base)).collect());
        out.extend(free.iter().map(|r| (*r, Ownership::Unallocated)));
        let deleted = fs
            .entries()
            .iter()
            .filter(|e| e.is_deleted())
            .flat_map(|e| e.extents.iter().filter_map(|x| Some(ByteRange::new(base + x.volume_offset?, x.len))));
        for d in deleted {
            out.extend(intersect(&free, d).map(|r| (r, Ownership::DeletedFile)));
        }
    }
    let mut covered: Vec<ByteRange> = volumes.iter().map(|v| v.range).collect();
    covered.sort();
    let mut cursor = 0;
    for c in covered.iter().chain(std::iter::once(&ByteRange::new(disk_len, 0))) {
        if c.start() > cursor {
            out.push((ByteRange::from_bounds(cursor, c.start().min(disk_len)), Ownership::OutsideVolumes));
        }
        cursor = cursor.max(c.end());
    }
    out
}

/// Parts of `r` inside the sorted, coalesced `ranges`.
fn intersect(ranges: &[ByteRange], r: ByteRange) -> impl Iterator<Item = ByteRange> + '_ {
    let first = ranges.partition_point(|x| x.end() <= r.start());
    ranges[first..].iter().take_while(move |x| x.start() < r.end()).filter_map(move |x| x.intersect(&r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersects_sorted_ranges() {
        let free = vec![ByteRange::new(0, 10), ByteRange::new(20, 10), ByteRange::new(40, 10)];
        let got: Vec<_> = intersect(&free, ByteRange::new(5, 40)).collect();
        assert_eq!(got, vec![ByteRange::new(5, 5), ByteRange::new(20, 10), ByteRange::new(40, 5)]);
        assert_eq!(intersect(&free, ByteRange::new(10, 10)).count(), 0);
    }
}
