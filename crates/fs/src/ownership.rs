use crate::{FileEntry, FileId};

/// Maps a volume byte offset back to the file(s) whose content covers it.
///
/// Built once per filesystem from every entry's extents (deleted entries included, so a hit in
/// unallocated space can still be attributed to the deleted file that used to live there).
pub struct OwnershipIndex {
    // (volume_start, volume_end, file, file_offset_at_start), sorted by start.
    spans: Vec<(u64, u64, FileId, u64)>,
}

impl OwnershipIndex {
    pub fn build(entries: &[FileEntry]) -> Self {
        let mut spans: Vec<_> = entries
            .iter()
            .enumerate()
            .flat_map(|(i, e)| {
                e.extents
                    .iter()
                    .filter_map(move |x| x.volume_offset.map(|v| (v, v + x.len, FileId::new(i), x.file_offset)))
            })
            .collect();
        spans.sort_unstable_by_key(|s| s.0);
        Self { spans }
    }

    /// Files covering `volume_offset`, live entries first, with the offset inside each file.
    pub fn owners(&self, volume_offset: u64, entries: &[FileEntry]) -> Vec<(FileId, u64)> {
        // Spans can overlap (deleted files over reused clusters), so scan back from the
        // partition point over spans that could still contain the offset.
        let end = self.spans.partition_point(|s| s.0 <= volume_offset);
        let mut out: Vec<(FileId, u64)> = self.spans[..end]
            .iter()
            .rev()
            .take(4096)
            .filter(|s| volume_offset < s.1)
            .map(|s| (s.2, s.3 + (volume_offset - s.0)))
            .collect();
        out.sort_by_key(|(id, _)| entries.get(id.index()).is_none_or(|e| e.is_deleted()));
        out.dedup_by_key(|(id, _)| *id);
        out
    }
}
