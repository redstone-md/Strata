//! File block mapping: ext4 extent trees (index + leaf nodes, uninitialized extents read as
//! zeros) and classic direct / indirect / double / triple block maps.

use super::inode::Inode;
use super::reader::BlockReader;
use crate::Extent;
use crate::alloc::ExtentList;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, DamageKind};

const EXTENT_MAGIC: u16 = 0xF30A;
const MAX_DEPTH: u16 = 5;
const UNINIT_LEN: u16 = 32768;
const DIRECT: usize = 12;
/// Extents per file beyond which the map is cut (damaged or adversarial trees).
const MAX_RUNS: usize = 1 << 20;

/// A file's content runs plus problems met while resolving them.
#[derive(Default)]
pub(super) struct Mapping {
    pub(super) extents: Vec<Extent>,
    pub(super) damage: Vec<Damage>,
}

pub(super) struct BlockMapper<'r, 'a> {
    reader: &'r BlockReader<'a>,
}

struct Walk {
    list: ExtentList,
    damage: Vec<Damage>,
    runs: usize,
    /// Logical blocks the file's size can cover; mapping stops there.
    wanted: u64,
}

impl<'r, 'a> BlockMapper<'r, 'a> {
    pub(super) fn new(reader: &'r BlockReader<'a>) -> Self {
        Self { reader }
    }

    /// Map `inode`'s content up to its size.
    pub(super) fn map(&self, inode: &Inode) -> Mapping {
        let bs = self.reader.sb().block_size();
        let size = inode.size();
        let mut w = Walk { list: ExtentList::default(), damage: Vec::new(), runs: 0, wanted: size.div_ceil(bs) };
        if inode.resident().is_some() || size == 0 {
            return Mapping::default();
        }
        if inode.uses_extents() {
            self.extent_node(inode.iblock(), inode.iblock_offset(), MAX_DEPTH + 1, &mut w);
        } else {
            self.block_map(inode, &mut w);
        }
        if w.list.end() == 0 && w.damage.is_empty() && !inode.is_deleted() {
            w.damage.push(Damage::missing(None, "non-empty file maps no blocks"));
        }
        Mapping { extents: w.list.finish(size, size), damage: w.damage }
    }

    fn extent_node(&self, node: &[u8], at: u64, depth_left: u16, w: &mut Walk) {
        let range = ByteRange::new(at, node.len() as u64);
        let (Some(EXTENT_MAGIC), Some(entries), Some(depth)) = (u16_le(node, 0), u16_le(node, 2), u16_le(node, 6)) else {
            w.damage.push(Damage::corrupt(range, "extent node header invalid"));
            return;
        };
        if depth >= depth_left {
            w.damage.push(Damage::corrupt(range, "extent tree deeper than allowed"));
            return;
        }
        let bs = self.reader.sb().block_size();
        for i in 0..usize::from(entries) {
            let e = 12 + i * 12;
            let Some(entry) = node.get(e..e + 12) else {
                w.damage.push(Damage::corrupt(range, "extent entries run past their node"));
                return;
            };
            if w.runs >= MAX_RUNS {
                w.damage.push(Damage::corrupt(range, "extent tree too large; mapping cut"));
                return;
            }
            let (Some(lblk), Some(lo), Some(hi16)) = (u32_le(entry, 0), u32_le(entry, 4), u16_le(entry, 8)) else { return };
            if depth > 0 {
                let child = u64::from(lo) | u64::from(hi16) << 32;
                match self.reader.block(child) {
                    Some(data) => self.extent_node(&data, child * bs, depth, w),
                    None => w.damage.push(Damage::new(
                        DamageKind::Unreadable,
                        Some(ByteRange::new(child.saturating_mul(bs), bs)),
                        "extent index block unreadable or out of range",
                    )),
                }
                continue;
            }
            let (Some(raw_len), Some(start_hi), Some(start_lo)) = (u16_le(entry, 4), u16_le(entry, 6), u32_le(entry, 8)) else { return };
            let (len, uninit) = if raw_len > UNINIT_LEN { (raw_len - UNINIT_LEN, true) } else { (raw_len, false) };
            let start = u64::from(start_lo) | u64::from(start_hi) << 32;
            let len = u64::from(len);
            if !self.reader.sb().is_block(start) || !self.reader.sb().is_block(start + len.saturating_sub(1)) {
                w.damage.push(Damage::corrupt(range, format!("extent at block {start} lies outside the volume")));
                continue;
            }
            let vol = (!uninit).then_some(start * bs);
            if !w.list.push_at(u64::from(lblk) * bs, vol, len * bs) {
                w.damage.push(Damage::corrupt(range, "overlapping extents"));
            }
            w.runs += 1;
        }
    }

    fn block_map(&self, inode: &Inode, w: &mut Walk) {
        let ptrs: Vec<u64> = inode.iblock().as_chunks::<4>().0.iter().map(|c| u64::from(u32::from_le_bytes(*c))).collect();
        for (i, p) in ptrs.iter().take(DIRECT).enumerate() {
            self.data_block(*p, i as u64, w);
        }
        let per = self.reader.sb().block_size() / 4;
        let mut first = DIRECT as u64;
        for (level, p) in ptrs.iter().skip(DIRECT).enumerate() {
            let span = per.saturating_pow(level as u32 + 1);
            self.indirect(*p, level as u32 + 1, first, w);
            first = first.saturating_add(span);
        }
    }

    fn data_block(&self, ptr: u64, lblk: u64, w: &mut Walk) {
        if ptr == 0 || lblk >= w.wanted {
            return;
        }
        let bs = self.reader.sb().block_size();
        if !self.reader.sb().is_block(ptr) {
            w.damage.push(Damage::new(DamageKind::Corrupt, None, format!("block pointer {ptr} outside the volume")));
            return;
        }
        w.list.push_at(lblk * bs, Some(ptr * bs), bs);
    }

    /// An indirect block of `level` (1 = single) whose first logical block is `first`.
    fn indirect(&self, ptr: u64, level: u32, first: u64, w: &mut Walk) {
        if ptr == 0 || first >= w.wanted {
            return;
        }
        let bs = self.reader.sb().block_size();
        let Some(data) = self.reader.sb().is_block(ptr).then(|| self.reader.block(ptr)).flatten() else {
            w.damage.push(Damage::missing(Some(ByteRange::new(ptr.saturating_mul(bs), bs)), "indirect block unreadable or out of range"));
            return;
        };
        let per = bs / 4;
        let span = per.saturating_pow(level - 1);
        for (i, c) in data.as_chunks::<4>().0.iter().enumerate() {
            let p = u64::from(u32::from_le_bytes(*c));
            let lblk = first.saturating_add((i as u64).saturating_mul(span));
            if lblk >= w.wanted || w.runs >= MAX_RUNS {
                return;
            }
            w.runs += 1;
            if level == 1 {
                self.data_block(p, lblk, w);
            } else {
                self.indirect(p, level - 1, lblk, w);
            }
        }
    }
}
