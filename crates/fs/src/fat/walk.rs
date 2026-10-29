//! Directory tree walk: live entries via cluster chains, deleted ones via the classic
//! contiguous-cluster heuristic.

use super::bpb::Bpb;
use super::dir::{self, DirBuffer, DirRecord};
use super::dirent::ShortEntry;
use super::table::{ChainEnd, FatTable};
use crate::alloc::{ClusterMap, ExtentList};
use crate::{EntryState, FileEntry, FileId};
use std::collections::{HashSet, VecDeque};
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;
use strata_volume::FsKind;

/// Directories larger than this are damaged (65536 entries is the FAT maximum: 2 MiB).
const MAX_DIR_BYTES: u64 = 2 << 20;
/// How far a deleted directory is followed past its first cluster.
const MAX_RECOVERED_DIR_CLUSTERS: u32 = 16;

#[derive(Clone, Copy)]
enum DirLoc {
    FixedRoot,
    Chain(u32),
    /// Deleted directory: start cluster, read contiguously while clusters stay free.
    Recovered(u32),
}

pub(super) struct Walker<'a> {
    source: &'a dyn BlockSource,
    bpb: &'a Bpb,
    fat: &'a FatTable,
    used: ClusterMap,
    entries: Vec<FileEntry>,
    damage: Vec<Damage>,
    visited: HashSet<u32>,
}

impl<'a> Walker<'a> {
    pub(super) fn new(source: &'a dyn BlockSource, bpb: &'a Bpb, fat: &'a FatTable) -> Self {
        let used = fat.used_map();
        Self { source, bpb, fat, used, entries: Vec::new(), damage: Vec::new(), visited: HashSet::new() }
    }

    pub(super) fn walk(mut self) -> (Vec<FileEntry>, ClusterMap, Vec<Damage>) {
        self.entries.push(FileEntry::new("", true, EntryState::Allocated, 0));
        let root = match self.bpb.kind() {
            FsKind::Fat32 => DirLoc::Chain(self.bpb.root_cluster()),
            _ => DirLoc::FixedRoot,
        };
        let mut queue = VecDeque::from([(0usize, root, false)]);
        while let Some((parent, loc, deleted)) = queue.pop_front() {
            let Some(buf) = self.read_dir(loc, parent) else { continue };
            for rec in dir::parse(&buf) {
                if let Some((idx, child)) = self.add(parent, rec, deleted) {
                    queue.push_back((idx, child, deleted || self.entries[idx].state != EntryState::Allocated));
                }
            }
        }
        (self.entries, self.used, self.damage)
    }

    fn fat32(&self) -> bool {
        self.bpb.kind() == FsKind::Fat32
    }

    fn is_used(&self, cluster: u32) -> bool {
        cluster >= 2 && self.used.is_used(u64::from(cluster - 2))
    }

    fn read_dir(&mut self, loc: DirLoc, owner: usize) -> Option<DirBuffer> {
        let mut buf = DirBuffer::default();
        match loc {
            DirLoc::FixedRoot => {
                let r = self.bpb.root_region();
                buf.push(r.start(), &self.source.read_vec(r.start(), r.len() as usize).ok()?);
            }
            DirLoc::Chain(start) => {
                let limit = (MAX_DIR_BYTES / self.bpb.cluster_size()).max(1) as usize;
                let chain = self.fat.chain(start, limit);
                if let ChainEnd::Broken(why) = chain.end() {
                    let at = self.cluster_range(start);
                    self.entries[owner].damage.push(Damage::corrupt(at, format!("directory {why}")));
                }
                self.read_clusters(chain.clusters(), &mut buf);
            }
            DirLoc::Recovered(start) => self.read_recovered_dir(start, owner, &mut buf)?,
        }
        Some(buf)
    }

    /// Read clusters, merging physically consecutive ones into single reads.
    fn read_clusters(&self, clusters: &[u32], buf: &mut DirBuffer) {
        let cs = self.bpb.cluster_size();
        let mut i = 0;
        while i < clusters.len() {
            let mut j = i + 1;
            while j < clusters.len() && clusters[j] == clusters[j - 1].wrapping_add(1) {
                j += 1;
            }
            if let Some(off) = self.bpb.cluster_offset(clusters[i]) {
                let data = self.source.read_vec(off, ((j - i) as u64 * cs) as usize).unwrap_or_default();
                buf.push(off, &data);
            }
            i = j;
        }
    }

    /// A deleted directory is trusted only if its first cluster still starts with its own `.`
    /// entry; following clusters are taken while free and still holding directory entries.
    fn read_recovered_dir(&mut self, start: u32, owner: usize, buf: &mut DirBuffer) -> Option<()> {
        let cs = self.bpb.cluster_size() as usize;
        let at = self.cluster_range(start);
        let first = self.source.read_vec(self.bpb.cluster_offset(start)?, cs).ok()?;
        let intact = ShortEntry::parse(&first).is_some_and(|s| s.is_self_entry(start));
        if !intact || self.is_used(start) {
            self.entries[owner].damage.push(Damage::missing(Some(at), "deleted directory overwritten; contents lost"));
            return None;
        }
        buf.push(at.start(), &first);
        for c in (start + 1..start.saturating_add(MAX_RECOVERED_DIR_CLUSTERS)).take_while(|c| self.bpb.is_cluster(*c)) {
            if self.is_used(c) {
                break;
            }
            let Some(off) = self.bpb.cluster_offset(c) else { break };
            let data = self.source.read_vec(off, cs).ok()?;
            let mut probe = DirBuffer::default();
            probe.push(off, &data);
            if dir::parse(&probe).is_empty() {
                break;
            }
            buf.push(off, &data);
        }
        Some(())
    }

    fn cluster_range(&self, cluster: u32) -> ByteRange {
        ByteRange::new(self.bpb.cluster_offset(cluster).unwrap_or(0), self.bpb.cluster_size())
    }

    /// Add a record under `parent`; returns the directory to descend into, if any.
    fn add(&mut self, parent: usize, mut rec: DirRecord, in_deleted_dir: bool) -> Option<(usize, DirLoc)> {
        let short = rec.short();
        let deleted = short.is_deleted() || in_deleted_dir;
        let state = if deleted { EntryState::Deleted } else { EntryState::Allocated };
        let mut entry = FileEntry::new(rec.name(), short.is_dir(), state, rec.offset());
        entry.parent = Some(FileId::new(parent));
        entry.path = match self.entries[parent].path.as_str() {
            "" => entry.name.clone(),
            p => format!("{p}/{}", entry.name),
        };
        entry.times = short.times();
        let cluster = self.first_cluster(short, deleted);
        let is_dir = short.is_dir();
        let size = u64::from(short.size());
        entry.damage = rec.take_damage();
        if !is_dir {
            entry.size = size;
            if deleted {
                self.recover_content(&mut entry, cluster);
            } else {
                self.chain_content(&mut entry, cluster);
            }
        }
        let idx = self.entries.len();
        self.entries.push(entry);
        if !is_dir || !self.bpb.is_cluster(cluster) || !self.visited.insert(cluster) {
            return None;
        }
        Some((idx, if deleted { DirLoc::Recovered(cluster) } else { DirLoc::Chain(cluster) }))
    }

    fn first_cluster(&self, short: &ShortEntry, deleted: bool) -> u32 {
        let full = short.cluster(self.fat32());
        if deleted && !self.bpb.is_cluster(full) && self.bpb.is_cluster(short.cluster_low()) {
            return short.cluster_low();
        }
        full
    }

    fn chain_content(&self, entry: &mut FileEntry, cluster: u32) {
        if entry.size == 0 {
            return;
        }
        let cs = self.bpb.cluster_size();
        let at = ByteRange::new(entry.native_id, 32);
        if !self.bpb.is_cluster(cluster) {
            entry.damage.push(Damage::corrupt(at, "non-empty file has no valid first cluster"));
            return;
        }
        let need = entry.size.div_ceil(cs) as usize;
        let chain = self.fat.chain(cluster, need);
        let mut list = ExtentList::default();
        for c in chain.clusters() {
            list.push(self.bpb.cluster_offset(*c), cs);
        }
        if let ChainEnd::Broken(why) = chain.end() {
            entry.damage.push(Damage::corrupt(at, format!("file {why}")));
        }
        if list.end() < entry.size {
            entry.damage.push(Damage::new(DamageKind::Truncated, Some(at), "cluster chain shorter than file size"));
        }
        entry.extents = list.finish(entry.size, entry.size);
    }

    /// Undelete heuristic: the file is assumed to occupy consecutive clusters from its first.
    fn recover_content(&self, entry: &mut FileEntry, cluster: u32) {
        if entry.size == 0 {
            return;
        }
        let cs = self.bpb.cluster_size();
        let Some(off) = self.bpb.cluster_offset(cluster) else {
            entry.damage.push(Damage::missing(None, "deleted file's first cluster is unknown"));
            return;
        };
        let wanted = entry.size.div_ceil(cs);
        let available = u64::from(self.bpb.max_cluster() - cluster + 1);
        let clusters = wanted.min(available);
        let range = ByteRange::new(off, clusters * cs);
        entry.extents = vec![crate::Extent { file_offset: 0, volume_offset: Some(off), len: entry.size.min(clusters * cs) }];
        if clusters < wanted {
            entry.damage.push(Damage::new(DamageKind::Truncated, Some(range), "deleted file runs past the volume end"));
        }
        if self.used.any_used(u64::from(cluster - 2), clusters) {
            entry.damage.push(Damage::missing(Some(range), "clusters now allocated to another file; content likely overwritten"));
        }
    }
}
