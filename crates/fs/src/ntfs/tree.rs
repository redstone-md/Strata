//! Places built files into a tree: parent links by file reference, `$Orphans` for files whose
//! parent is gone or reused, and full paths.

use super::assemble::Built;
use super::record::FileRef;
pub(super) use crate::tree::ORPHANS;
use crate::tree::resolve_paths;
use crate::{EntryState, FileEntry, FileId};
use std::collections::HashMap;

const ROOT_RECORD: u64 = 5;

struct Slot {
    parent: Option<FileRef>,
    seq: u16,
    in_use: bool,
}

#[derive(Default)]
pub(super) struct TreeBuilder {
    entries: Vec<FileEntry>,
    slots: Vec<Slot>,
    by_record: HashMap<u64, usize>,
    compressed: HashMap<usize, u64>,
}

impl TreeBuilder {
    /// Add a file from the live `$MFT`.
    pub(super) fn add(&mut self, built: Built) {
        let idx = self.entries.len();
        if let Some(unit) = built.compression_unit() {
            self.compressed.insert(idx, unit);
        }
        self.slots.push(Slot { parent: built.parent(), seq: built.seq(), in_use: built.in_use() });
        let entry = built.into_entry();
        self.by_record.entry(entry.native_id).or_insert(idx);
        self.entries.push(entry);
    }

    /// Resolve parents and paths. Returns the entries and the compressed-entry table.
    pub(super) fn finish(mut self) -> (Vec<FileEntry>, HashMap<usize, u64>) {
        let root = match self.by_record.get(&ROOT_RECORD) {
            Some(&r) => r,
            None => self.push_virtual("", ROOT_RECORD, EntryState::Allocated),
        };
        let orphans = self.push_virtual(ORPHANS, u64::MAX, EntryState::Orphan);
        for i in 0..self.entries.len() {
            let parent = if i == root {
                None
            } else if i == orphans {
                Some(root)
            } else {
                Some(self.resolve_parent(i).unwrap_or(orphans))
            };
            self.entries[i].parent = parent.map(FileId::new);
        }
        self.entries[root].name.clear();
        resolve_paths(&mut self.entries, root, orphans);
        (self.entries, self.compressed)
    }

    fn push_virtual(&mut self, name: &str, native_id: u64, state: EntryState) -> usize {
        self.slots.push(Slot { parent: None, seq: 0, in_use: true });
        self.entries.push(FileEntry::new(name, true, state, native_id));
        self.entries.len() - 1
    }

    fn resolve_parent(&self, i: usize) -> Option<usize> {
        let slot = &self.slots[i];
        let parent = slot.parent?;
        let &target = self.by_record.get(&parent.record())?;
        let t = &self.slots[target];
        (target != i && self.entries[target].is_dir && parent.points_to(t.seq, t.in_use)).then_some(target)
    }
}
