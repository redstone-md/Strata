//! Directory tree walk: live sets through FAT chains or `NoFatChain` runs, deleted sets
//! through the contiguous-cluster assumption checked against the allocation bitmap.

use super::boot::ExfatBoot;
use super::dir::{self, Listing, Record};
use crate::alloc::{ClusterMap, ExtentList};
use crate::dirbuf::DirBuffer;
use crate::entry::join_path;
use crate::fat::table::{ChainEnd, FatTable};
use crate::heap::ClusterHeap;
use crate::{EntryState, Extent, FileEntry, FileId};
use std::collections::{HashSet, VecDeque};
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

/// Directories are read at most this far (exFAT allows 256 MiB; real ones are far smaller).
const MAX_DIR_BYTES: u64 = 8 << 20;

#[derive(Clone, Copy)]
enum DirLoc {
    Chain(u32, u64),
    Contiguous(u32, u64),
    /// Deleted directory: contiguous, trusted only while its clusters are still free.
    Recovered(u32, u64),
}

/// What a walk produced.
pub(super) struct Walked {
    pub(super) entries: Vec<FileEntry>,
    pub(super) used: ClusterMap,
    pub(super) damage: Vec<Damage>,
    pub(super) label: Option<String>,
}

pub(super) struct Walker<'a> {
    source: &'a dyn BlockSource,
    boot: &'a ExfatBoot,
    fat: &'a FatTable,
    used: ClusterMap,
    entries: Vec<FileEntry>,
    damage: Vec<Damage>,
    visited: HashSet<u32>,
}

impl<'a> Walker<'a> {
    pub(super) fn new(source: &'a dyn BlockSource, boot: &'a ExfatBoot, fat: &'a FatTable) -> Self {
        let used = fat.used_map();
        Self { source, boot, fat, used, entries: Vec::new(), damage: Vec::new(), visited: HashSet::new() }
    }

    pub(super) fn walk(mut self) -> Walked {
        self.entries.push(FileEntry::new("", true, EntryState::Allocated, 0));
        let root = self.boot.root_cluster();
        self.visited.insert(root);
        let root_buf = self.read_dir(DirLoc::Chain(root, MAX_DIR_BYTES), 0).unwrap_or_default();
        let listing = dir::parse(&root_buf);
        self.used = self.load_bitmap(listing.bitmap);
        let label = listing.label.clone();
        let mut queue = VecDeque::new();
        self.add_listing(0, listing, false, &mut queue);
        while let Some((parent, loc, deleted)) = queue.pop_front() {
            if let Some(buf) = self.read_dir(loc, parent) {
                self.add_listing(parent, dir::parse(&buf), deleted, &mut queue);
            }
        }
        Walked { entries: self.entries, used: self.used, damage: self.damage, label }
    }

    fn heap(&self) -> &'a ClusterHeap {
        self.boot.heap()
    }

    fn add_listing(&mut self, parent: usize, listing: Listing, deleted: bool, queue: &mut VecDeque<(usize, DirLoc, bool)>) {
        for rec in &listing.records {
            if let Some((idx, loc)) = self.add(parent, rec, deleted) {
                queue.push_back((idx, loc, self.entries[idx].state != EntryState::Allocated));
            }
        }
    }

    /// The allocation bitmap (one bit per cluster from cluster 2); the FAT is the fallback.
    fn load_bitmap(&mut self, bitmap: Option<(u32, u64)>) -> ClusterMap {
        let count = u64::from(self.heap().count());
        let Some((first, len)) = bitmap else {
            self.damage.push(Damage::missing(None, "allocation bitmap entry missing; free space taken from the FAT"));
            return self.fat.used_map();
        };
        let want = len.min(count.div_ceil(8));
        let need = self.heap().clusters_for(want);
        let chain = self.fat.chain(first, need as usize);
        let clusters = match chain.clusters().len() as u64 >= need {
            true => chain.clusters().to_vec(),
            // Bitmaps are normally contiguous; a broken chain is read as a run.
            false => self.heap().run(first, need),
        };
        if (clusters.len() as u64) < need {
            self.damage.push(Damage::missing(None, "allocation bitmap outside the volume; free space taken from the FAT"));
            return self.fat.used_map();
        }
        let mut buf = DirBuffer::default();
        self.heap().read_clusters(self.source, &clusters, &mut buf);
        ClusterMap::from_lsb_bytes(buf.bytes(), count)
    }

    fn read_dir(&mut self, loc: DirLoc, owner: usize) -> Option<DirBuffer> {
        let heap = self.heap();
        let clusters_for = |len: u64| heap.clusters_for(len.clamp(1, MAX_DIR_BYTES));
        let clusters = match loc {
            DirLoc::Chain(first, len) => {
                let chain = self.fat.chain(first, clusters_for(len) as usize);
                if let ChainEnd::Broken(why) = chain.end() {
                    let at = heap.cluster_range(first);
                    self.entries[owner].damage.push(Damage::corrupt(at, format!("directory {why}")));
                }
                chain.clusters().to_vec()
            }
            DirLoc::Contiguous(first, len) => heap.run(first, clusters_for(len)),
            DirLoc::Recovered(first, len) => {
                let run = heap.run(first, clusters_for(len));
                if run.is_empty() || self.used.any_used(u64::from(first - 2), run.len() as u64) {
                    let at = heap.cluster_range(first);
                    self.entries[owner].damage.push(Damage::missing(Some(at), "deleted directory overwritten; contents lost"));
                    return None;
                }
                run
            }
        };
        let mut buf = DirBuffer::default();
        heap.read_clusters(self.source, &clusters, &mut buf);
        Some(buf)
    }

    /// Add a record under `parent`; returns the directory to descend into, if any.
    fn add(&mut self, parent: usize, rec: &Record, in_deleted_dir: bool) -> Option<(usize, DirLoc)> {
        let set = rec.set();
        let deleted = set.is_deleted() || in_deleted_dir;
        let state = if deleted { EntryState::Deleted } else { EntryState::Allocated };
        let name = match set.name() {
            "" => format!("$exfat_{:x}", rec.offset()),
            n => n.to_string(),
        };
        let mut entry = FileEntry::new(name, set.is_dir(), state, rec.offset());
        entry.parent = Some(FileId::new(parent));
        entry.path = join_path(&self.entries[parent].path, &entry.name);
        entry.times = set.times();
        let at = ByteRange::new(rec.offset(), rec.span());
        if !set.is_complete() {
            entry.damage.push(Damage::new(DamageKind::Truncated, Some(at), "entry set incomplete; name or stream entries overwritten"));
        } else if !set.checksum_ok() {
            entry.damage.push(Damage::corrupt(at, "entry set checksum mismatch"));
        }
        if !set.is_dir() {
            entry.size = set.data_length();
            entry.extents = self.content(set, deleted, at, &mut entry.damage);
        }
        let idx = self.entries.len();
        self.entries.push(entry);
        let first = set.first_cluster();
        if !set.is_dir() || !self.heap().is_cluster(first) || !self.visited.insert(first) {
            return None;
        }
        let len = set.data_length();
        let loc = match (deleted, set.is_contiguous()) {
            (true, _) => DirLoc::Recovered(first, len),
            (false, true) => DirLoc::Contiguous(first, len),
            (false, false) => DirLoc::Chain(first, len),
        };
        Some((idx, loc))
    }

    fn content(&self, set: &super::entry::FileSet, deleted: bool, at: ByteRange, damage: &mut Vec<Damage>) -> Vec<Extent> {
        let size = set.data_length();
        if size == 0 {
            return Vec::new();
        }
        let heap = self.heap();
        let first = set.first_cluster();
        let mut list = ExtentList::default();
        if deleted || set.is_contiguous() {
            let (extents, notes) = heap.contiguous(first, size, &self.used, deleted);
            damage.extend(notes);
            for x in extents {
                list.push_at(x.file_offset, x.volume_offset, x.len);
            }
        } else if !heap.is_cluster(first) {
            damage.push(Damage::corrupt(at, "non-empty file has no valid first cluster"));
        } else {
            let chain = self.fat.chain(first, heap.clusters_for(size) as usize);
            list = heap.extents_of(chain.clusters());
            if let ChainEnd::Broken(why) = chain.end() {
                damage.push(Damage::corrupt(at, format!("file {why}")));
            }
            if list.end() < size {
                damage.push(Damage::new(DamageKind::Truncated, Some(at), "cluster chain shorter than file size"));
            }
        }
        list.finish(size, set.valid_length())
    }
}
