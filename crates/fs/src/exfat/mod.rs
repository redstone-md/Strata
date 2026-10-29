//! exFAT: boot region checksums, FAT, allocation bitmap, entry sets (live and deleted).
//!
//! The up-case table is not needed for listing and is not read.

mod boot;
mod dir;
mod entry;
mod walk;

#[cfg(test)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::fat::table::FatTable;
use crate::tree::FsTree;
use boot::ExfatBoot;
use std::sync::Arc;
use strata_kernel::{Error, Result};
use strata_source::BlockSource;
use strata_volume::FsKind;
use walk::Walker;

/// Parse an exFAT volume.
pub(crate) fn open(source: Arc<dyn BlockSource>) -> Result<FsTree> {
    let src = source.as_ref();
    let (boot, mut damage) = ExfatBoot::locate(src);
    let boot = boot.ok_or_else(|| Error::format("no valid exFAT boot sector"))?;
    let (fat, fat_damage) = FatTable::load(src, &boot.fat_layout());
    damage.extend(fat_damage);
    let walked = Walker::new(src, &boot, &fat).walk();
    damage.extend(walked.damage);
    let heap = boot.heap();
    let unallocated = walked.used.free_ranges(heap.start(), heap.cluster_size());
    Ok(FsTree::new(FsKind::ExFat, source, walked.entries, unallocated, damage).with_label(walked.label))
}
