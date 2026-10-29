//! JBD2 journal mining for undelete. ext3/4 wipe a deleted inode's block pointers, but the
//! journal often still holds older copies of the inode-table block from before the delete.
//! Every descriptor block in the journal (live or stale) is followed to its data blocks; inode
//! table copies yield the newest intact version of each deleted inode of the same generation.

use super::blockmap::BlockMapper;
use super::groups::Groups;
use super::inode::Inode;
use super::inodes::InodeStore;
use super::reader::BlockReader;
use std::collections::HashMap;
use strata_kernel::bytes::u32_be;
use strata_kernel::{Damage, DamageKind};

const MAGIC: u32 = 0xC03B_3998;
const DESCRIPTOR: u32 = 1;
const SB_V1: u32 = 3;
const SB_V2: u32 = 4;
const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_CSUM_V2: u32 = 0x8;
const INCOMPAT_CSUM_V3: u32 = 0x10;
const TAG_ESCAPE: u32 = 0x1;
const TAG_SAME_UUID: u32 = 0x2;
const TAG_LAST: u32 = 0x8;
/// Journals larger than this are not mined (metadata-only budget).
const MAX_JOURNAL: u64 = 1 << 30;

/// Older intact copies of deleted inodes, by inode number, with their transaction sequence.
#[derive(Default)]
pub(super) struct JournalCopies {
    copies: HashMap<u32, (u32, Inode)>,
}

struct Layout {
    block_size: usize,
    first: usize,
    max_len: usize,
    tag_size: usize,
    flags_be32: bool,
    tail: usize,
}

impl JournalCopies {
    pub(super) fn get(&self, ino: u32) -> Option<(u32, &Inode)> {
        self.copies.get(&ino).map(|(seq, i)| (*seq, i))
    }

    pub(super) fn scan(reader: &BlockReader, groups: &Groups, store: &InodeStore) -> (Self, Vec<Damage>) {
        let sb = reader.sb();
        let Some(jinode) = store.get(sb.journal_inode()).filter(|i| !i.is_deleted() && i.is_regular()) else {
            return (Self::default(), Vec::new());
        };
        if jinode.size() > MAX_JOURNAL {
            return (Self::default(), vec![Damage::new(DamageKind::Missing, None, "journal larger than 1 GiB; not mined for deleted inodes")]);
        }
        let mapping = BlockMapper::new(reader).map(jinode);
        let mut journal = vec![0u8; jinode.size() as usize];
        for ext in &mapping.extents {
            let (Some(vol), Ok(at)) = (ext.volume_offset, usize::try_from(ext.file_offset)) else { continue };
            if let Ok(data) = reader.source().read_vec(vol, ext.len as usize)
                && let Some(dst) = journal.get_mut(at..at + data.len())
            {
                dst.copy_from_slice(&data);
            }
        }
        let Some(layout) = Layout::parse(&journal) else {
            return (Self::default(), vec![Damage::new(DamageKind::Corrupt, None, "journal superblock invalid; journal not mined")]);
        };
        let mut out = Self::default();
        let index = TableIndex::new(reader, groups);
        for j in layout.first..layout.max_len {
            let Some(block) = layout.block(&journal, j) else { break };
            if u32_be(block, 0) == Some(MAGIC) && u32_be(block, 4) == Some(DESCRIPTOR) {
                let seq = u32_be(block, 8).unwrap_or(0);
                for (k, (fs_block, escaped)) in layout.tags(block).into_iter().enumerate() {
                    let Some(data) = layout.block(&journal, layout.wrap(j + 1 + k)) else { continue };
                    if let Some((group, slot0)) = index.find(fs_block) {
                        let mut data = data.to_vec();
                        if escaped {
                            data[..4].copy_from_slice(&MAGIC.to_be_bytes());
                        }
                        out.examine(&data, group, slot0, seq, reader, store);
                    }
                }
            }
        }
        (out, Vec::new())
    }

    fn examine(&mut self, block: &[u8], group: u64, slot0: u64, seq: u32, reader: &BlockReader, store: &InodeStore) {
        let sb = reader.sb();
        let isz = sb.inode_size() as usize;
        for (i, raw) in block.chunks_exact(isz).enumerate() {
            let ino = group * u64::from(sb.inodes_per_group()) + slot0 + i as u64 + 1;
            let Ok(ino) = u32::try_from(ino) else { return };
            let Some(current) = store.get(ino) else { continue };
            if !current.is_deleted() || current.has_pointers() || current.resident().is_some() {
                continue;
            }
            let Some(copy) = Inode::parse(raw, ino, current.offset()) else { continue };
            let same_file = copy.generation() == current.generation() && copy.file_type() == current.file_type();
            if !same_file || copy.is_deleted() || !copy.has_pointers() {
                continue;
            }
            match self.copies.get(&ino) {
                Some((old, _)) if *old >= seq => {}
                _ => {
                    self.copies.insert(ino, (seq, copy));
                }
            }
        }
    }
}

impl Layout {
    fn parse(journal: &[u8]) -> Option<Self> {
        if u32_be(journal, 0)? != MAGIC || !matches!(u32_be(journal, 4)?, SB_V1 | SB_V2) {
            return None;
        }
        let block_size = u32_be(journal, 0x0C)? as usize;
        let max_len = (u32_be(journal, 0x10)? as usize).min(journal.len() / block_size.max(1));
        let first = u32_be(journal, 0x14)? as usize;
        if !(1024..=65536).contains(&block_size) || first == 0 || first >= max_len {
            return None;
        }
        let incompat = if u32_be(journal, 4)? == SB_V2 { u32_be(journal, 0x28)? } else { 0 };
        let csum = incompat & (INCOMPAT_CSUM_V2 | INCOMPAT_CSUM_V3) != 0;
        let tag_size = if incompat & INCOMPAT_CSUM_V3 != 0 {
            16
        } else {
            8 + if incompat & INCOMPAT_CSUM_V2 != 0 { 2 } else { 0 } + if incompat & INCOMPAT_64BIT != 0 { 4 } else { 0 }
        };
        Some(Self { block_size, first, max_len, tag_size, flags_be32: incompat & INCOMPAT_CSUM_V3 != 0, tail: if csum { 4 } else { 0 } })
    }

    fn block<'j>(&self, journal: &'j [u8], j: usize) -> Option<&'j [u8]> {
        journal.get(j.checked_mul(self.block_size)?..(j + 1).checked_mul(self.block_size)?)
    }

    /// The journal is circular between `first` and `max_len`.
    fn wrap(&self, j: usize) -> usize {
        if j < self.max_len { j } else { self.first + (j - self.max_len) % (self.max_len - self.first) }
    }

    /// `(filesystem block, escaped)` for each tag of a descriptor block.
    fn tags(&self, block: &[u8]) -> Vec<(u64, bool)> {
        let mut out = Vec::new();
        let mut at = 12;
        let end = block.len().saturating_sub(self.tail);
        while at + self.tag_size <= end {
            let lo = u64::from(u32_be(block, at).unwrap_or(0));
            let flags = if self.flags_be32 {
                u32_be(block, at + 4).unwrap_or(TAG_LAST)
            } else {
                u32::from(strata_kernel::bytes::u16_be(block, at + 6).unwrap_or(TAG_LAST as u16))
            };
            let hi = if self.tag_size >= 12 { u64::from(u32_be(block, at + 8).unwrap_or(0)) } else { 0 };
            out.push((hi << 32 | lo, flags & TAG_ESCAPE != 0));
            at += self.tag_size + if flags & TAG_SAME_UUID == 0 { 16 } else { 0 };
            if flags & TAG_LAST != 0 {
                break;
            }
        }
        out
    }
}

/// Filesystem block -> (group, first inode slot in that block) for inode-table blocks.
struct TableIndex {
    tables: Vec<(u64, u64, u64)>,
    per_block: u64,
}

impl TableIndex {
    fn new(reader: &BlockReader, groups: &Groups) -> Self {
        let blocks = reader.sb().itable_blocks();
        let mut tables: Vec<(u64, u64, u64)> =
            (0..groups.len()).filter_map(|g| groups.get(g).map(|d| (d.inode_table(), d.inode_table() + blocks, g))).collect();
        tables.sort_unstable();
        Self { tables, per_block: (reader.sb().block_size() / reader.sb().inode_size()).max(1) }
    }

    fn find(&self, block: u64) -> Option<(u64, u64)> {
        let i = self.tables.partition_point(|t| t.0 <= block).checked_sub(1)?;
        let (start, end, group) = self.tables[i];
        (block < end).then(|| (group, (block - start) * self.per_block))
    }
}
