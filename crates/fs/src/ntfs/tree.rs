//! Places built files into a tree: parent links by file reference, `$Orphans` for files whose
//! parent is gone or reused, and full paths.

use crate::entry::join_path;
use super::assemble::Built;
use super::record::FileRef;
use crate::{EntryState, FileEntry, FileId};
use std::collections::HashMap;

const ROOT_RECORD: u64 = 5;
pub(super) const ORPHANS: &str = "$Orphans";

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

/// Fill `path` for every entry; break parent cycles by moving the looping entry to `$Orphans`.
/// Entries hanging directly under `$Orphans` get [`EntryState::Orphan`].
pub(super) fn resolve_paths(entries: &mut [FileEntry], root: usize, orphans: usize) {
    let n = entries.len();
    let mut done = vec![false; n];
    let mut mark = vec![usize::MAX; n];
    entries[root].path.clear();
    entries[orphans].path = entries[orphans].name.clone();
    done[root] = true;
    done[orphans] = true;
    for start in 0..n {
        let mut chain = Vec::new();
        let mut cur = start;
        while !done[cur] {
            if mark[cur] == start {
                // Cycle: cut it at the entry that led back here.
                let last = chain.pop().unwrap_or(cur);
                entries[last].parent = Some(FileId::new(orphans));
                chain.push(last);
                break;
            }
            mark[cur] = start;
            chain.push(cur);
            cur = match entries[cur].parent.map(FileId::index).filter(|p| *p < n) {
                Some(p) => p,
                None => {
                    entries[cur].parent = Some(FileId::new(orphans));
                    orphans
                }
            };
        }
        for &i in chain.iter().rev() {
            let p = entries[i].parent.map_or(root, FileId::index);
            entries[i].path = join_path(&entries[p].path, &entries[i].name);
            if p == orphans && i != orphans {
                entries[i].state = EntryState::Orphan;
            }
            done[i] = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, parent: Option<usize>) -> FileEntry {
        let mut e = FileEntry::new(name, true, EntryState::Allocated, 0);
        e.parent = parent.map(FileId::new);
        e
    }

    #[test]
    fn cycles_end_up_under_orphans() {
        let mut entries = vec![entry("", None), entry(ORPHANS, Some(0)), entry("a", Some(3)), entry("b", Some(2)), entry("c", Some(0))];
        resolve_paths(&mut entries, 0, 1);
        assert_eq!(entries[4].path, "c");
        let paths: Vec<&str> = entries[2..4].iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"$Orphans/a") || paths.contains(&"$Orphans/b"), "{paths:?}");
        assert!(paths.iter().all(|p| p.starts_with("$Orphans/")));
    }
}
