//! Block group descriptors (32- or 64-byte), with per-descriptor fallback to the backup table in
//! group 1, and the block/inode bitmaps they point to.

use super::reader::BlockReader;
use super::superblock::Superblock;
use crate::alloc::ClusterMap;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, DamageKind};

const INODE_UNINIT: u16 = 0x1;
const BLOCK_UNINIT: u16 = 0x2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GroupDesc {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    flags: u16,
    itable_unused: u64,
}

impl GroupDesc {
    fn parse(d: &[u8], wide: bool) -> Option<Self> {
        let hi32 = |off: usize| if wide { u32_le(d, off).map(u64::from) } else { Some(0) };
        let hi16 = |off: usize| if wide { u16_le(d, off).map(u64::from) } else { Some(0) };
        Some(Self {
            block_bitmap: u64::from(u32_le(d, 0x00)?) | hi32(0x20)? << 32,
            inode_bitmap: u64::from(u32_le(d, 0x04)?) | hi32(0x24)? << 32,
            inode_table: u64::from(u32_le(d, 0x08)?) | hi32(0x28)? << 32,
            flags: u16_le(d, 0x12)?,
            itable_unused: u64::from(u16_le(d, 0x1C)?) | hi16(0x32)? << 16,
        })
    }

    fn valid(&self, sb: &Superblock) -> bool {
        let table_end = self.inode_table.saturating_add(sb.itable_blocks());
        sb.is_block(self.block_bitmap) && sb.is_block(self.inode_bitmap) && sb.is_block(self.inode_table) && table_end <= sb.blocks_count()
    }

    pub(super) fn inode_table(&self) -> u64 {
        self.inode_table
    }
}

pub(super) struct Groups {
    descs: Vec<Option<GroupDesc>>,
    csum: bool,
    ipg: u64,
}

impl Groups {
    pub(super) fn load(reader: &BlockReader) -> (Self, Vec<Damage>) {
        let sb = reader.sb();
        let count = sb.group_count();
        let primary = Self::read_table(reader, sb.group());
        let mut backup: Option<Vec<Option<GroupDesc>>> = None;
        let (mut repaired, mut lost) = (0u64, 0u64);
        let mut descs = Vec::with_capacity(count as usize);
        for g in 0..count {
            if let Some(d) = primary.get(g as usize).copied().flatten().filter(|d| d.valid(sb)) {
                descs.push(Some(d));
                continue;
            }
            let backup = backup.get_or_insert_with(|| if sb.group() == 0 && count > 1 { Self::read_table(reader, 1) } else { Vec::new() });
            let fallback = backup.get(g as usize).copied().flatten().filter(|d| d.valid(sb));
            if fallback.is_some() { repaired += 1 } else { lost += 1 }
            descs.push(fallback);
        }
        let mut damage = Vec::new();
        if repaired > 0 {
            damage.push(Damage::new(DamageKind::Corrupt, None, format!("{repaired} group descriptors invalid; backup copies used")));
        }
        if lost > 0 {
            damage.push(Damage::new(DamageKind::Corrupt, None, format!("{lost} of {count} group descriptors unusable; their inodes are skipped")));
        }
        (Self { descs, csum: sb.has_group_csum(), ipg: u64::from(sb.inodes_per_group()) }, damage)
    }

    /// Descriptor table stored after the superblock copy of `copy_group` (descriptors beyond
    /// `first_meta_bg` are read from their meta groups instead).
    fn read_table(reader: &BlockReader, copy_group: u64) -> Vec<Option<GroupDesc>> {
        let sb = reader.sb();
        let ds = sb.desc_size();
        let per_block = sb.block_size() / ds;
        let count = sb.group_count();
        let plain = count.min(sb.first_meta_bg().saturating_mul(per_block));
        // The table follows the superblock copy's block (block 2 for 1 KiB blocks, else 1).
        let table_block = sb.group_first_block(copy_group) + 1;
        let blocks = (plain * ds).div_ceil(sb.block_size());
        let raw = reader.blocks(table_block, blocks).unwrap_or_default();
        let mut out: Vec<Option<GroupDesc>> =
            (0..plain).map(|g| raw.get((g * ds) as usize..((g + 1) * ds) as usize).and_then(|d| GroupDesc::parse(d, sb.is_64bit()))).collect();
        let mut g = plain;
        while g < count {
            let meta_first = g - g % per_block;
            let block = sb.group_first_block(meta_first) + u64::from(sb.has_super(meta_first));
            let data = reader.block(block).unwrap_or_default();
            for slot in 0..per_block.min(count - g) {
                out.push(data.get((slot * ds) as usize..((slot + 1) * ds) as usize).and_then(|d| GroupDesc::parse(d, sb.is_64bit())));
            }
            g += per_block;
        }
        out
    }

    pub(super) fn len(&self) -> u64 {
        self.descs.len() as u64
    }

    pub(super) fn get(&self, group: u64) -> Option<&GroupDesc> {
        self.descs.get(group as usize)?.as_ref()
    }

    /// Inode slots of `group` that may ever have been used (`itable_unused` trims the
    /// never-touched tail when group checksums make it trustworthy).
    pub(super) fn used_slots(&self, group: u64) -> u64 {
        match self.get(group) {
            Some(d) if self.csum && d.flags & INODE_UNINIT != 0 => 0,
            Some(d) if self.csum => self.ipg.saturating_sub(d.itable_unused),
            Some(_) => self.ipg,
            None => 0,
        }
    }

    /// Block allocation across the volume (index 0 = `first_data_block`). Unreadable bitmaps
    /// count as fully used so they never show up as free space.
    pub(super) fn block_map(&self, reader: &BlockReader) -> (ClusterMap, Vec<Damage>) {
        let sb = reader.sb();
        let bytes_per_group = (sb.blocks_per_group() / 8) as usize;
        let runs: Vec<(u64, u64)> = self.descs.iter().map(|d| (d.map_or(0, |d| d.block_bitmap), 1)).collect();
        let data = reader.batch(&runs);
        let mut all = Vec::with_capacity(bytes_per_group * self.descs.len());
        let mut damage = Vec::new();
        for (g, (desc, bits)) in self.descs.iter().zip(data).enumerate() {
            let chunk = match (desc, bits) {
                (Some(d), _) if self.csum && d.flags & BLOCK_UNINIT != 0 => vec![0u8; bytes_per_group],
                (Some(_), Some(b)) => b,
                (Some(d), None) => {
                    let at = ByteRange::new(d.block_bitmap * sb.block_size(), sb.block_size());
                    damage.push(Damage::new(DamageKind::Unreadable, Some(at), format!("block bitmap of group {g} unreadable")));
                    vec![0xFF; bytes_per_group]
                }
                (None, _) => vec![0xFF; bytes_per_group],
            };
            all.extend(chunk.iter().take(bytes_per_group));
            all.resize(bytes_per_group * (g + 1), 0xFF);
        }
        (ClusterMap::from_lsb_bytes(&all, sb.blocks_count().saturating_sub(sb.first_data_block())), damage)
    }

    /// Inode allocation (index 0 = inode 1). `None` where the bitmap could not be read.
    pub(super) fn inode_map(&self, reader: &BlockReader) -> (ClusterMap, Vec<bool>) {
        let sb = reader.sb();
        let ipg = self.ipg as usize;
        let bytes = ipg.div_ceil(8);
        let runs: Vec<(u64, u64)> = self.descs.iter().map(|d| (d.map_or(0, |d| d.inode_bitmap), 1)).collect();
        let data = reader.batch(&runs);
        let mut all = Vec::with_capacity(bytes * self.descs.len());
        let mut known = Vec::with_capacity(self.descs.len());
        for (desc, bits) in self.descs.iter().zip(data) {
            let chunk = match desc {
                Some(d) if self.csum && d.flags & INODE_UNINIT != 0 => Some(vec![0u8; bytes]),
                Some(_) => bits,
                None => None,
            };
            known.push(chunk.is_some());
            let mut chunk = chunk.unwrap_or_default();
            chunk.resize(bytes, 0);
            all.extend(chunk.iter().take(bytes));
        }
        // Groups are `ipg` bits apart; when ipg is not a byte multiple, repack bit by bit.
        let map = if ipg.is_multiple_of(8) {
            ClusterMap::from_lsb_bytes(&all, u64::from(sb.inodes_count()))
        } else {
            let mut map = ClusterMap::new(u64::from(sb.inodes_count()));
            for g in 0..self.descs.len() {
                for i in 0..ipg {
                    if all.get(g * bytes + i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0) {
                        map.set_used((g * ipg + i) as u64);
                    }
                }
            }
            map
        };
        (map, known)
    }
}
