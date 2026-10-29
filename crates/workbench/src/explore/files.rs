//! Browsing parsed filesystems: directory trees for the left pane and flat, filterable file
//! lists for the right one. Lists hold entry indexes only and build rows on demand, so a
//! 700,000-entry volume costs a few megabytes.

use std::sync::Arc;
use strata_case::{EvidenceLayout, FileTypes};
use strata_fs::{EntryState, FileEntry, FileId, FileSystem};
use strata_identify::{Category, Registry};
use strata_kernel::{EvidenceId, Timestamp};
use strata_volume::VolumeOrigin;

/// Which entries a list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFilter {
    All,
    Deleted,
    Orphan,
    /// Content type does not match the extension.
    Renamed,
    /// Content type of one category (from the classify step).
    Type(Category),
}

#[derive(Debug, Clone)]
pub struct FileListQuery {
    pub evidence: EvidenceId,
    pub volume: u32,
    /// Directory entry index; `None` = the volume root.
    pub dir: Option<usize>,
    pub filter: FileFilter,
    /// Part of the name, any case; empty = no name filter.
    pub name: String,
}

impl FileListQuery {
    /// Plain folder view: no filter, no name. Anything else lists the whole subtree.
    fn is_folder_view(&self) -> bool {
        self.filter == FileFilter::All && self.name.trim().is_empty()
    }
}

/// One row of a file list.
#[derive(Debug, Clone)]
pub struct FileView {
    pub evidence: EvidenceId,
    pub volume: u32,
    pub index: usize,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub state: EntryState,
    pub detected_type: Option<String>,
    pub extension_mismatch: bool,
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
    pub damaged: bool,
    /// The volume is a recovered (deleted) partition.
    pub in_deleted_partition: bool,
}

/// A directory in the tree pane.
#[derive(Debug, Clone)]
pub struct DirNode {
    pub index: usize,
    pub name: String,
    pub state: EntryState,
    pub has_subdirs: bool,
}

/// The entries a query selected, rows built on demand.
#[derive(Clone)]
pub struct FileListing {
    layout: Arc<EvidenceLayout>,
    types: Arc<FileTypes>,
    evidence: EvidenceId,
    volume: u32,
    ids: Arc<Vec<u32>>,
}

impl FileListing {
    pub(crate) fn build(layout: Arc<EvidenceLayout>, types: Arc<FileTypes>, q: &FileListQuery) -> Self {
        let ids = layout.filesystem(q.volume).map(|(_, fs)| select(fs, &types, q)).unwrap_or_default();
        Self { layout, types, evidence: q.evidence, volume: q.volume, ids: Arc::new(ids) }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn row(&self, i: usize) -> Option<FileView> {
        let index = *self.ids.get(i)? as usize;
        let (vol, fs) = self.layout.filesystem(self.volume)?;
        let e = fs.entry(FileId::new(index))?;
        let ty = self.types.get(&(self.volume, index));
        Some(FileView {
            evidence: self.evidence,
            volume: self.volume,
            index,
            name: e.name.clone(),
            path: e.path.clone(),
            size: e.size,
            is_dir: e.is_dir,
            state: e.state,
            detected_type: ty.map(|t| t.0.clone()),
            extension_mismatch: ty.is_some_and(|t| t.1),
            created: e.times.created,
            modified: e.times.modified,
            accessed: e.times.accessed,
            damaged: !e.damage.is_empty(),
            in_deleted_partition: vol.origin == VolumeOrigin::Recovered,
        })
    }

    /// Sort rows by a key built from each row (stable; the key is computed once per row).
    pub fn sort_by_key<K: Ord>(&mut self, descending: bool, key: impl Fn(&FileEntry) -> K) {
        let Some((_, fs)) = self.layout.filesystem(self.volume) else { return };
        let mut keyed: Vec<(K, u32)> = self.ids.iter().filter_map(|i| Some((key(fs.entry(FileId::new(*i as usize))?), *i))).collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        if descending {
            keyed.reverse();
        }
        self.ids = Arc::new(keyed.into_iter().map(|(_, i)| i).collect());
    }
}

/// Content category of a stored type name.
pub fn type_category(type_name: &str) -> Option<Category> {
    Registry::all().iter().find(|t| t.name == type_name).map(|t| t.category)
}

fn root(fs: &dyn FileSystem) -> Option<usize> {
    fs.entries().iter().position(|e| e.parent.is_none() && e.is_dir)
}

/// Subdirectories of `dir` (`None` = root), folders first by name.
pub(crate) fn subdirs(fs: &dyn FileSystem, dir: Option<usize>) -> Vec<DirNode> {
    let Some(dir) = dir.or_else(|| root(fs)) else { return Vec::new() };
    let mut out: Vec<DirNode> = fs
        .children(FileId::new(dir))
        .into_iter()
        .filter(|c| c.index() != dir)
        .filter_map(|c| {
            let e = fs.entry(c)?;
            e.is_dir.then(|| DirNode {
                index: c.index(),
                name: e.name.clone(),
                state: e.state,
                has_subdirs: fs.children(c).iter().any(|g| g.index() != c.index() && fs.entry(*g).is_some_and(|x| x.is_dir)),
            })
        })
        .collect();
    out.sort_by_key(|d| (d.state != EntryState::Allocated, d.name.to_lowercase()));
    out
}

fn select(fs: &dyn FileSystem, types: &FileTypes, q: &FileListQuery) -> Vec<u32> {
    let Some(dir) = q.dir.or_else(|| root(fs)) else { return Vec::new() };
    if q.is_folder_view() {
        let mut ids: Vec<FileId> = fs.children(FileId::new(dir)).into_iter().filter(|c| c.index() != dir).collect();
        ids.sort_by_key(|c| fs.entry(*c).map(|e| (!e.is_dir, e.name.to_lowercase())));
        return ids.into_iter().map(|c| c.index() as u32).collect();
    }
    let prefix = fs.entry(FileId::new(dir)).map(|d| d.path.clone()).unwrap_or_default();
    let name = q.name.trim().to_lowercase();
    fs.entries()
        .iter()
        .enumerate()
        .filter(|(i, e)| *i != dir && (prefix.is_empty() || e.path.strip_prefix(&prefix).is_some_and(|r| r.starts_with('/'))))
        .filter(|(_, e)| name.is_empty() || e.name.to_lowercase().contains(&name))
        .filter(|(i, e)| keep(q.filter, e, types.get(&(q.volume, *i))))
        .map(|(i, _)| i as u32)
        .collect()
}

fn keep(filter: FileFilter, e: &FileEntry, ty: Option<&(String, bool)>) -> bool {
    match filter {
        FileFilter::All => true,
        FileFilter::Deleted => e.state == EntryState::Deleted,
        FileFilter::Orphan => e.state == EntryState::Orphan,
        FileFilter::Renamed => ty.is_some_and(|t| t.1),
        FileFilter::Type(c) => ty.and_then(|t| type_category(&t.0)) == Some(c),
    }
}
