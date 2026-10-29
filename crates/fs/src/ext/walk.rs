//! Directory tree walk from the root inode, breadth first with each level's directory blocks
//! read in disk order. Deleted names come from directory slack; their inodes give times and,
//! where pointers survive (ext2) or the journal kept an older copy, content. In-use inodes no
//! directory references end up under `$Orphans`.

use super::blockmap::{BlockMapper, Mapping};
use super::dir::{DirParser, DirRecord};
use super::inode::{IBLOCK_LEN, Inode};
use super::inodes::InodeStore;
use super::journal::JournalCopies;
use super::reader::BlockReader;
use crate::alloc::ClusterMap;
use crate::tree::{ORPHANS, resolve_paths};
use crate::{EntryState, Extent, FileEntry, FileId};
use std::collections::HashSet;
use strata_kernel::{ByteRange, Damage, DamageKind};

const ROOT_INODE: u32 = 2;
/// Directories larger than this are cut (damaged sizes, adversarial trees).
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Directories read per batch, so one huge level does not hold all its blocks at once.
const DIRS_PER_BATCH: usize = 4096;
const FT_DIR: u8 = 2;

/// A directory waiting to be read.
struct DirJob {
    entry: usize,
    deleted: bool,
    htree: bool,
    resident: Option<(u64, Vec<u8>)>,
    extents: Vec<Extent>,
}

pub(super) struct Walker<'r, 'a> {
    reader: &'r BlockReader<'a>,
    store: &'r InodeStore,
    journal: &'r JournalCopies,
    blocks: &'r ClusterMap,
    parser: DirParser,
    entries: Vec<FileEntry>,
    damage: Vec<Damage>,
    referenced: HashSet<u32>,
    visited: HashSet<u32>,
}

impl<'r, 'a> Walker<'r, 'a> {
    pub(super) fn new(reader: &'r BlockReader<'a>, store: &'r InodeStore, journal: &'r JournalCopies, blocks: &'r ClusterMap) -> Self {
        let sb = reader.sb();
        Self {
            reader,
            store,
            journal,
            blocks,
            parser: DirParser::new(sb.has_filetype(), sb.inodes_count()),
            entries: Vec::new(),
            damage: Vec::new(),
            referenced: HashSet::new(),
            visited: HashSet::new(),
        }
    }

    pub(super) fn walk(mut self) -> (Vec<FileEntry>, Vec<Damage>) {
        self.entries.push(FileEntry::new("", true, EntryState::Allocated, u64::from(ROOT_INODE)));
        match self.store.get(ROOT_INODE).filter(|i| i.is_dir()).cloned() {
            Some(root) => {
                self.referenced.insert(ROOT_INODE);
                let job = self.fill(0, &root, false);
                self.run(job.into_iter().collect());
            }
            None => self.damage.push(Damage::new(DamageKind::Missing, None, "root directory inode missing; tree rebuilt from orphans")),
        }
        let orphans = self.entries.len();
        let mut folder = FileEntry::new(ORPHANS, true, EntryState::Orphan, u64::MAX);
        folder.parent = Some(FileId::new(0));
        self.entries.push(folder);
        self.adopt_orphans(orphans);
        resolve_paths(&mut self.entries, 0, orphans);
        (self.entries, self.damage)
    }

    /// Unreferenced inodes: live directories first (with their subtrees), then live files, then
    /// deleted inodes that still have content.
    fn adopt_orphans(&mut self, orphans: usize) {
        let first = self.reader.sb().first_ino();
        let candidates: Vec<(u32, bool, bool)> = self
            .store
            .iter()
            .filter(|i| i.ino() >= first && !self.referenced.contains(&i.ino()))
            .map(|i| (i.ino(), i.is_dir(), self.store.in_use(i.ino()) && !i.is_deleted()))
            .collect();
        let passes: [&dyn Fn(bool, bool) -> bool; 3] = [&|dir, live| dir && live, &|dir, live| !dir && live, &|_, live| !live];
        for pass in passes {
            for &(ino, dir, live) in &candidates {
                if !pass(dir, live) || self.referenced.contains(&ino) {
                    continue;
                }
                let Some(inode) = self.store.get(ino).cloned() else { continue };
                if !live && !inode.has_pointers() && self.journal.get(ino).is_none() {
                    continue;
                }
                let state = if live { EntryState::Allocated } else { EntryState::Deleted };
                let mut entry = FileEntry::new(format!("#{ino}"), dir, state, u64::from(ino));
                entry.parent = Some(FileId::new(orphans));
                self.referenced.insert(ino);
                self.entries.push(entry);
                let job = self.fill(self.entries.len() - 1, &inode, !live);
                self.run(job.into_iter().collect());
            }
        }
    }

    fn run(&mut self, mut frontier: Vec<DirJob>) {
        while !frontier.is_empty() {
            frontier.sort_by_key(|j| j.extents.iter().find_map(|e| e.volume_offset).unwrap_or(u64::MAX));
            let mut next = Vec::new();
            for batch in frontier.chunks(DIRS_PER_BATCH) {
                let records = self.read_batch(batch);
                for (job, recs) in batch.iter().zip(records) {
                    for rec in recs {
                        next.extend(self.add(job.entry, rec, job.deleted));
                    }
                }
            }
            frontier = next;
        }
    }

    /// Directory records of every job, reading all their blocks in one merged pass.
    fn read_batch(&mut self, jobs: &[DirJob]) -> Vec<Vec<DirRecord>> {
        let bs = self.reader.sb().block_size();
        let mut runs = Vec::new();
        let mut owner = Vec::new();
        for (j, job) in jobs.iter().enumerate() {
            let mut budget = MAX_DIR_BYTES;
            for ext in job.extents.iter().filter(|e| e.volume_offset.is_some()) {
                let len = ext.len.min(budget).div_ceil(bs);
                budget = budget.saturating_sub(len * bs);
                runs.push((ext.volume_offset.unwrap_or(0) / bs, len));
                owner.push(j);
            }
        }
        let data = self.reader.batch(&runs);
        let mut blocks: Vec<Vec<(u64, Vec<u8>)>> = vec![Vec::new(); jobs.len()];
        for ((run, j), bytes) in runs.iter().zip(owner).zip(data) {
            match bytes {
                Some(bytes) => blocks[j].extend(bytes.chunks(bs as usize).enumerate().map(|(i, b)| ((run.0 + i as u64) * bs, b.to_vec()))),
                None => {
                    let at = ByteRange::new(run.0.saturating_mul(bs), run.1.saturating_mul(bs));
                    self.entries[jobs[j].entry].damage.push(Damage::new(DamageKind::Unreadable, Some(at), "directory blocks unreadable"));
                }
            }
        }
        jobs.iter()
            .zip(blocks)
            .map(|(job, blocks)| match &job.resident {
                Some((at, data)) => self.parser.parse_inline(data, *at),
                None => {
                    let view: Vec<(u64, &[u8])> = blocks.iter().map(|(at, b)| (*at, b.as_slice())).collect();
                    self.parser.parse(&view, job.htree)
                }
            })
            .collect()
    }

    /// Add one directory record under `parent`; returns the directory to read next, if any.
    fn add(&mut self, parent: usize, rec: DirRecord, in_deleted: bool) -> Option<DirJob> {
        let deleted = rec.deleted || in_deleted;
        let state = if deleted { EntryState::Deleted } else { EntryState::Allocated };
        let mut entry = FileEntry::new(rec.name, rec.file_type == FT_DIR, state, u64::from(rec.inode));
        entry.parent = Some(FileId::new(parent));
        let at = Some(ByteRange::new(rec.offset, 8));
        let inode = (rec.inode != 0).then(|| self.store.get(rec.inode)).flatten().cloned();
        let usable = match &inode {
            None if rec.inode == 0 => {
                entry.damage.push(Damage::missing(at, "inode number cleared on delete; name only"));
                None
            }
            None => {
                entry.damage.push(Damage::missing(at, format!("inode {} never written or unreadable", rec.inode)));
                None
            }
            Some(i) if deleted && (!i.matches_dirent_type(rec.file_type) || (self.store.in_use(i.ino()) && !i.is_deleted())) => {
                entry.damage.push(Damage::missing(at, "inode now belongs to a live file (renamed or reused); name only"));
                None
            }
            Some(i) => {
                if !deleted && !self.store.in_use(i.ino()) {
                    entry.damage.push(Damage::corrupt(ByteRange::new(rec.offset, 8), "live entry points to a free inode"));
                }
                Some(i)
            }
        };
        self.entries.push(entry);
        let idx = self.entries.len() - 1;
        let inode = usable?;
        self.referenced.insert(inode.ino());
        self.fill(idx, inode, deleted)
    }

    /// Copy inode metadata and content into entry `idx`; returns a job if it is a directory to
    /// descend into.
    fn fill(&mut self, idx: usize, inode: &Inode, deleted: bool) -> Option<DirJob> {
        let mapper = BlockMapper::new(self.reader);
        let mut damage = Vec::new();
        let mut source = inode;
        let resident = inode.resident();
        let mut mapping = Mapping::default();
        if resident.is_none() {
            if deleted && !inode.has_pointers() {
                if let Some((_, copy)) = self.journal.get(inode.ino()) {
                    source = copy;
                    damage.push(Damage::missing(None, "content pointers recovered from an older journal copy of the inode"));
                } else {
                    let when = inode.dtime().map(|t| format!(" on {t}")).unwrap_or_default();
                    damage.push(Damage::missing(None, format!("content pointers wiped (ext3/4 delete){when}")));
                }
            }
            mapping = mapper.map(source);
            damage.append(&mut mapping.damage);
            if deleted && self.overwritten(&mapping.extents) {
                damage.push(Damage::missing(None, "blocks now allocated to another file; content likely overwritten"));
            }
        }
        let entry = &mut self.entries[idx];
        entry.is_dir = inode.is_dir();
        entry.times = inode.times();
        entry.damage.extend(damage);
        if inode.is_dir() {
            let descend = self.visited.insert(inode.ino()) && (resident.is_some() || !mapping.extents.is_empty());
            let resident = resident.map(|r| (inode.iblock_offset(), r));
            return descend.then_some(DirJob { entry: idx, deleted, htree: inode.is_htree(), resident, extents: mapping.extents });
        }
        entry.size = source.size();
        if let Some(data) = resident {
            entry.resident_offset = (data.len() <= IBLOCK_LEN).then(|| inode.iblock_offset());
            entry.resident = Some(data);
        } else {
            entry.extents = mapping.extents;
        }
        None
    }

    /// Whether any block of a deleted file's extents is allocated again.
    fn overwritten(&self, extents: &[Extent]) -> bool {
        let sb = self.reader.sb();
        let bs = sb.block_size();
        extents.iter().filter_map(|e| e.volume_offset.map(|v| (v / bs, e.len.div_ceil(bs)))).any(|(block, count)| {
            block.checked_sub(sb.first_data_block()).is_some_and(|i| self.blocks.any_used(i, count))
        })
    }
}
