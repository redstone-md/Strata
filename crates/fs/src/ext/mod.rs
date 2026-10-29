//! ext2/3/4: superblock (with backups), group descriptors, inode tables, extent trees and block
//! maps, inline data, directory walk with deleted entries from dirent slack, orphan inodes and
//! journal mining for the content pointers ext3/4 wipe on delete.

mod blockmap;
mod dir;
mod groups;
mod inode;
mod inodes;
mod journal;
mod reader;
mod superblock;
mod walk;

#[cfg(test)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::tree::FsTree;
use groups::Groups;
use inodes::InodeStore;
use journal::JournalCopies;
use reader::BlockReader;
use std::sync::Arc;
use strata_kernel::{Error, Result};
use strata_source::BlockSource;
use superblock::Superblock;
use walk::Walker;

/// Parse an ext volume (the flavour is taken from its own superblock).
pub(crate) fn open(source: Arc<dyn BlockSource>) -> Result<FsTree> {
    let (sb, mut damage) = Superblock::locate(source.as_ref());
    let sb = sb.ok_or_else(|| Error::format("no valid ext superblock"))?;
    let reader = BlockReader::new(source.as_ref(), &sb);
    let (groups, group_damage) = Groups::load(&reader);
    damage.extend(group_damage);
    let (store, inode_damage) = InodeStore::load(&reader, &groups);
    damage.extend(inode_damage);
    if store.len() == 0 {
        return Err(Error::format("ext volume has no readable inodes"));
    }
    let (blocks, bitmap_damage) = groups.block_map(&reader);
    damage.extend(bitmap_damage);
    let (journal, journal_damage) = JournalCopies::scan(&reader, &groups, &store);
    damage.extend(journal_damage);
    let (entries, walk_damage) = Walker::new(&reader, &store, &journal, &blocks).walk();
    damage.extend(walk_damage);
    let bs = sb.block_size();
    let unallocated = blocks.free_ranges(sb.first_data_block() * bs, bs);
    Ok(FsTree::new(sb.kind(), source, entries, unallocated, damage))
}
