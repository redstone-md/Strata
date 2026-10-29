//! Every inode that was ever used, read group by group from the inode tables (only up to the
//! high-water mark when group checksums make `itable_unused` trustworthy), plus allocation state
//! from the inode bitmaps.

use super::groups::Groups;
use super::inode::Inode;
use super::reader::BlockReader;
use crate::alloc::ClusterMap;
use strata_kernel::{ByteRange, Damage, DamageKind};

/// Inode tables read per batch (flex groups keep up to 16 tables back to back).
const GROUPS_PER_BATCH: u64 = 16;

pub(super) struct InodeStore {
    /// Sorted by inode number.
    inodes: Vec<Inode>,
    in_use: ClusterMap,
    bitmap_known: Vec<bool>,
    ipg: u32,
}

impl InodeStore {
    pub(super) fn load(reader: &BlockReader, groups: &Groups) -> (Self, Vec<Damage>) {
        let sb = reader.sb();
        let (bs, isz, ipg) = (sb.block_size(), sb.inode_size(), sb.inodes_per_group());
        let (in_use, bitmap_known) = groups.inode_map(reader);
        let mut inodes = Vec::new();
        let mut damage = Vec::new();
        let mut first = 0;
        while first < groups.len() {
            let batch: Vec<u64> = (first..groups.len().min(first + GROUPS_PER_BATCH)).collect();
            let runs: Vec<(u64, u64)> = batch
                .iter()
                .map(|&g| match groups.get(g) {
                    Some(d) => (d.inode_table(), (groups.used_slots(g) * isz).div_ceil(bs)),
                    None => (0, 0),
                })
                .collect();
            let tables = reader.batch(&runs);
            for ((&g, run), table) in batch.iter().zip(&runs).zip(tables) {
                if run.1 == 0 {
                    continue;
                }
                let Some(table) = table else {
                    let at = ByteRange::new(run.0.saturating_mul(bs), run.1.saturating_mul(bs));
                    damage.push(Damage::new(DamageKind::Unreadable, Some(at), format!("inode table of group {g} unreadable")));
                    continue;
                };
                for slot in 0..groups.used_slots(g) {
                    let off = (slot * isz) as usize;
                    let Some(raw) = table.get(off..off + isz as usize) else { break };
                    let ino = g * u64::from(ipg) + slot + 1;
                    let Ok(ino) = u32::try_from(ino) else { break };
                    if let Some(inode) = Inode::parse(raw, ino, run.0 * bs + off as u64) {
                        inodes.push(inode);
                    }
                }
            }
            first += GROUPS_PER_BATCH;
        }
        (Self { inodes, in_use, bitmap_known, ipg }, damage)
    }

    pub(super) fn get(&self, ino: u32) -> Option<&Inode> {
        self.inodes.binary_search_by_key(&ino, Inode::ino).ok().map(|i| &self.inodes[i])
    }

    /// Allocated per the inode bitmap; where the bitmap is unreadable, per the inode itself.
    pub(super) fn in_use(&self, ino: u32) -> bool {
        let group = ino.saturating_sub(1) / self.ipg.max(1);
        if self.bitmap_known.get(group as usize).copied().unwrap_or(false) {
            return self.in_use.is_used(u64::from(ino.saturating_sub(1)));
        }
        self.get(ino).is_some_and(|i| !i.is_deleted())
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Inode> {
        self.inodes.iter()
    }

    pub(super) fn len(&self) -> usize {
        self.inodes.len()
    }
}
