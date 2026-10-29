//! The parsed result every filesystem parser produces.

use crate::{FileEntry, FileId, FileSystem};
use std::sync::Arc;
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;
use strata_volume::FsKind;

/// Entries, free space and metadata damage of one walked filesystem.
pub(crate) struct FsTree {
    kind: FsKind,
    source: Arc<dyn BlockSource>,
    entries: Vec<FileEntry>,
    children: Vec<Vec<FileId>>,
    unallocated: Vec<ByteRange>,
    damage: Vec<Damage>,
    label: Option<String>,
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
        Self { kind, source, entries, children, unallocated: ByteRange::coalesce(unallocated), damage, label: None }
    }

    pub(crate) fn with_label(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
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

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}
