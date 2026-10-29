//! The parsed result every filesystem parser produces, and the shared path builder.

use crate::{EntryState, FileEntry, FileId, FileSystem};
use std::sync::Arc;
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;
use strata_volume::FsKind;

/// Name of the virtual folder holding entries whose parent chain is gone.
pub(crate) const ORPHANS: &str = "$Orphans";

/// Entries, free space and metadata damage of one walked filesystem.
pub(crate) struct FsTree {
    kind: FsKind,
    source: Arc<dyn BlockSource>,
    entries: Vec<FileEntry>,
    children: Vec<Vec<FileId>>,
    unallocated: Vec<ByteRange>,
    damage: Vec<Damage>,
}

impl FsTree {
    pub(crate) fn new(
        kind: FsKind,
        source: Arc<dyn BlockSource>,
        entries: Vec<FileEntry>,
        unallocated: Vec<ByteRange>,
        damage: Vec<Damage>,
    ) -> Self {
        let mut children = vec![Vec::new(); entries.len()];
        for (i, e) in entries.iter().enumerate() {
            if let Some(list) = e.parent.and_then(|p| children.get_mut(p.index())) {
                list.push(FileId::new(i));
            }
        }
        Self { kind, source, entries, children, unallocated: ByteRange::coalesce(unallocated), damage }
    }
}

impl FileSystem for FsTree {
    fn kind(&self) -> FsKind {
        self.kind
    }

    fn source(&self) -> &Arc<dyn BlockSource> {
        &self.source
    }

    fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    fn children(&self, dir: FileId) -> Vec<FileId> {
        self.children.get(dir.index()).cloned().unwrap_or_default()
    }

    fn unallocated(&self) -> Vec<ByteRange> {
        self.unallocated.clone()
    }

    fn damage(&self) -> &[Damage] {
        &self.damage
    }
}

/// Fill `path` for every entry; break parent cycles by moving the looping entry to `$Orphans`.
/// Entries hanging directly under `$Orphans` get [`EntryState::Orphan`].
pub(crate) fn resolve_paths(entries: &mut [FileEntry], root: usize, orphans: usize) {
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
            let path = if entries[p].path.is_empty() {
                entries[i].name.clone()
            } else {
                format!("{}/{}", entries[p].path, entries[i].name)
            };
            entries[i].path = path;
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
