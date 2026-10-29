//! FAT12/16/32: BPB, both FAT copies, directory walk with long names and deleted entries.

mod bpb;
mod dir;
mod dirent;
pub(crate) mod table;
mod walk;

#[cfg(test)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::tree::FsTree;
use bpb::Bpb;
use std::sync::Arc;
use strata_kernel::{Error, Result};
use strata_source::BlockSource;
use table::FatTable;
use walk::Walker;

/// Parse a FAT volume (the variant is taken from its own BPB).
pub(crate) fn open(source: Arc<dyn BlockSource>) -> Result<FsTree> {
    let src = source.as_ref();
    let (bpb, mut damage) = Bpb::locate(src);
    let bpb = bpb.ok_or_else(|| Error::format("no valid FAT boot sector"))?;
    let (fat, fat_damage) = FatTable::load(src, &bpb.fat_layout());
    damage.extend(fat_damage);
    let (entries, used, walk_damage) = Walker::new(src, &bpb, &fat).walk();
    damage.extend(walk_damage);
    let unallocated = used.free_ranges(bpb.heap().start(), bpb.heap().cluster_size());
    Ok(FsTree::new(bpb.kind(), source, entries, unallocated, damage))
}
