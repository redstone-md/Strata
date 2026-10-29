//! Free clusters: from `$Bitmap`, or rebuilt from live files when `$Bitmap` is unusable.

use super::boot::NtfsBoot;
use crate::alloc::ClusterMap;
use crate::{EntryState, Extent, ExtentReader, FileEntry};
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

const BITMAP_RECORD: u64 = 6;

pub(super) fn unallocated(
    source: &dyn BlockSource,
    boot: &NtfsBoot,
    entries: &[FileEntry],
    mft_extents: &[Extent],
) -> (Vec<ByteRange>, Vec<Damage>) {
    let cs = boot.cluster_size();
    if let Some(map) = from_bitmap(source, boot, entries) {
        return (map.free_ranges(0, cs), Vec::new());
    }
    let mut map = ClusterMap::new(boot.total_clusters());
    map.set_used(0);
    let live = entries.iter().filter(|e| e.state == EntryState::Allocated);
    for ext in live.flat_map(|e| e.extents.iter().chain(e.streams.iter().flat_map(|s| s.1.iter()))).chain(mft_extents) {
        if let Some(v) = ext.volume_offset {
            map.set_used_range(v / cs, (v % cs + ext.len).div_ceil(cs));
        }
    }
    let note = Damage::new(DamageKind::Corrupt, None, "$Bitmap unusable; free space rebuilt from live files");
    (map.free_ranges(0, cs), vec![note])
}

fn from_bitmap(source: &dyn BlockSource, boot: &NtfsBoot, entries: &[FileEntry]) -> Option<ClusterMap> {
    let entry = entries.iter().find(|e| e.native_id == BITMAP_RECORD && e.state == EntryState::Allocated)?;
    let need = boot.total_clusters().div_ceil(8);
    if entry.size < need {
        return None;
    }
    let bytes = ExtentReader::new(source, entry).read_all(usize::try_from(need).ok()?).ok()?;
    let map = ClusterMap::from_lsb_bytes(&bytes, boot.total_clusters());
    // Cluster 0 holds the boot sector and is always in use; a zero-filled (unreadable)
    // bitmap would otherwise declare the whole volume free.
    map.is_used(0).then_some(map)
}
