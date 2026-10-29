use crate::{FileEntry, FileId};

/// Maps a volume byte offset back to the file(s) whose content covers it.
///
/// Built once per filesystem from every entry's extents (deleted entries included, so a hit in
/// unallocated space can still be attributed to the deleted file that used to live there).
pub struct OwnershipIndex {
    // (volume_start, volume_end, file, file_offset_at_start), sorted by start.
    spans: Vec<(u64, u64, FileId, u64)>,
    /// `reach[i]` = max end of `spans[..=i]`; lets lookups stop as soon as no earlier span
    /// can still cover the offset, however long ago it started.
    reach: Vec<u64>,
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
        let reach = spans
            .iter()
            .scan(0u64, |max, s| {
                *max = (*max).max(s.1);
                Some(*max)
            })
            .collect();
        Self { spans, reach }
    }

    /// Files covering `volume_offset`, live entries first, with the offset inside each file.
    pub fn owners(&self, volume_offset: u64, entries: &[FileEntry]) -> Vec<(FileId, u64)> {
            let end = self.spans.partition_point(|s| s.0 <= volume_offset);
        let mut out: Vec<(FileId, u64)> = (0..end)
            .rev()
            .take_while(|&i| self.reach[i] > volume_offset)
            .map(|i| &self.spans[i])
            .filter(|s| volume_offset < s.1)
            .map(|s| (s.2, s.3 + (volume_offset - s.0)))
            .collect();
        out.sort_by_key(|(id, _)| entries.get(id.index()).is_none_or(|e| e.is_deleted()));
        out.dedup_by_key(|(id, _)| *id);
        out
    }
}
