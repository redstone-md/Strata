//! ext2/3/4 superblock: geometry and features, from the primary copy or a backup in a later
//! block group when the primary is damaged.

use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;
use strata_volume::{BootSector, FsKind};

const PRIMARY_OFFSET: u64 = 1024;
const SB_LEN: usize = 1024;
const ROOT_INODE: u32 = 2;
const JOURNAL_INODE: u32 = 8;

const COMPAT_SPARSE_SUPER2: u32 = 0x200;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_GDT_CSUM: u32 = 0x10;
const RO_COMPAT_METADATA_CSUM: u32 = 0x400;

/// Groups whose backup superblock is tried when the primary is unusable (sparse_super layout).
const BACKUP_GROUPS: [u64; 12] = [1, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343];

#[derive(Debug, Clone)]
pub(super) struct Superblock {
    kind: FsKind,
    block_size: u64,
    blocks_count: u64,
    first_data_block: u64,
    blocks_per_group: u64,
    inodes_per_group: u32,
    inodes_count: u32,
    inode_size: u64,
    desc_size: u64,
    first_ino: u32,
    first_meta_bg: u64,
    journal_inode: u32,
    compat: u32,
    incompat: u32,
    ro_compat: u32,
    /// Block group this copy was read from (0 = primary).
    group: u64,
}

impl Superblock {
    pub(super) fn parse(sb: &[u8], group: u64) -> Option<Self> {
        let boot = BootSector::ext_superblock(sb)?;
        let block_size = 1024u64 << u32_le(sb, 0x18)?;
        let rev = u32_le(sb, 0x4C)?;
        let (inode_size, first_ino) = if rev == 0 { (128, 11) } else { (u64::from(u16_le(sb, 0x58)?), u32_le(sb, 0x54)?) };
        if !(128..=block_size).contains(&inode_size) || !inode_size.is_power_of_two() {
            return None;
        }
        let incompat = u32_le(sb, 0x60)?;
        let desc_size = match u16_le(sb, 0xFE)? {
            d if incompat & INCOMPAT_64BIT != 0 && d >= 64 && u64::from(d) <= block_size && d.is_power_of_two() => u64::from(d),
            _ if incompat & INCOMPAT_64BIT != 0 => 64,
            _ => 32,
        };
        let journal_inode = match u32_le(sb, 0xE0)? {
            0 => JOURNAL_INODE,
            n => n,
        };
        Some(Self {
            kind: boot.kind,
            block_size,
            blocks_count: boot.declared_len / block_size,
            first_data_block: u64::from(u32_le(sb, 0x14)?),
            blocks_per_group: u64::from(u32_le(sb, 0x20)?),
            inodes_per_group: u32_le(sb, 0x28)?,
            inodes_count: u32_le(sb, 0x00)?,
            inode_size,
            desc_size,
            first_ino: first_ino.max(ROOT_INODE + 1),
            first_meta_bg: u64::from(u32_le(sb, 0x104)?),
            journal_inode,
            compat: u32_le(sb, 0x5C)?,
            incompat,
            ro_compat: u32_le(sb, 0x64)?,
            group,
        })
    }

    /// Primary superblock, else the first intact backup (with a damage note).
    pub(super) fn locate(source: &dyn BlockSource) -> (Option<Self>, Vec<Damage>) {
        let read = |off: u64, group: u64| source.read_vec(off, SB_LEN).ok().and_then(|b| Self::parse(&b, group));
        if let Some(sb) = read(PRIMARY_OFFSET, 0) {
            return (Some(sb), Vec::new());
        }
        let mut damage = vec![Damage::corrupt(ByteRange::new(PRIMARY_OFFSET, SB_LEN as u64), "primary ext superblock invalid")];
        // Backups sit at the start of their group; geometry is unknown, so try the standard
        // layout (blocks_per_group = 8 * block_size) for every block size.
        for log in 0..=6u32 {
            let bs = 1024u64 << log;
            let first = u64::from(log == 0);
            for g in BACKUP_GROUPS {
                let off = (first + g * bs * 8) * bs;
                if off >= source.len() {
                    break;
                }
                let found = read(off, g).filter(|sb| sb.block_size == bs && sb.backup_group_matches(source, off, g));
                if let Some(sb) = found {
                    damage.push(Damage::corrupt(ByteRange::new(off, SB_LEN as u64), format!("using backup superblock from group {g}")));
                    return (Some(sb), damage);
                }
            }
        }
        (None, damage)
    }

    fn backup_group_matches(&self, source: &dyn BlockSource, off: u64, group: u64) -> bool {
        let nr = source.read_vec(off + 0x5A, 2).ok().and_then(|b| u16_le(&b, 0));
        nr.is_some_and(|n| u64::from(n) == group) && self.group_first_block(group) * self.block_size == off
    }

    pub(super) fn kind(&self) -> FsKind {
        self.kind
    }

    pub(super) fn block_size(&self) -> u64 {
        self.block_size
    }

    pub(super) fn blocks_count(&self) -> u64 {
        self.blocks_count
    }

    pub(super) fn first_data_block(&self) -> u64 {
        self.first_data_block
    }

    pub(super) fn blocks_per_group(&self) -> u64 {
        self.blocks_per_group
    }

    pub(super) fn inodes_per_group(&self) -> u32 {
        self.inodes_per_group
    }

    pub(super) fn inodes_count(&self) -> u32 {
        self.inodes_count
    }

    pub(super) fn inode_size(&self) -> u64 {
        self.inode_size
    }

    pub(super) fn desc_size(&self) -> u64 {
        self.desc_size
    }

    pub(super) fn first_ino(&self) -> u32 {
        self.first_ino
    }

    pub(super) fn journal_inode(&self) -> u32 {
        self.journal_inode
    }

    /// Group the superblock in use was read from.
    pub(super) fn group(&self) -> u64 {
        self.group
    }

    pub(super) fn has_filetype(&self) -> bool {
        self.incompat & INCOMPAT_FILETYPE != 0
    }

    pub(super) fn is_64bit(&self) -> bool {
        self.incompat & INCOMPAT_64BIT != 0
    }

    /// Group descriptors carry `itable_unused` and the UNINIT flags.
    pub(super) fn has_group_csum(&self) -> bool {
        self.ro_compat & (RO_COMPAT_GDT_CSUM | RO_COMPAT_METADATA_CSUM) != 0
    }

    /// Group index from which descriptors live in meta block groups (`u64::MAX` = never).
    pub(super) fn first_meta_bg(&self) -> u64 {
        if self.incompat & INCOMPAT_META_BG != 0 { self.first_meta_bg } else { u64::MAX }
    }

    pub(super) fn group_count(&self) -> u64 {
        self.blocks_count.saturating_sub(self.first_data_block).div_ceil(self.blocks_per_group)
    }

    pub(super) fn group_first_block(&self, group: u64) -> u64 {
        self.first_data_block.saturating_add(group.saturating_mul(self.blocks_per_group))
    }

    /// Blocks one group's inode table occupies.
    pub(super) fn itable_blocks(&self) -> u64 {
        (u64::from(self.inodes_per_group) * self.inode_size).div_ceil(self.block_size)
    }

    /// Whether `group` holds a superblock copy (and, outside meta_bg, a descriptor table copy).
    pub(super) fn has_super(&self, group: u64) -> bool {
        if group <= 1 || self.ro_compat & RO_COMPAT_SPARSE_SUPER == 0 {
            return group <= 1 || self.compat & COMPAT_SPARSE_SUPER2 == 0;
        }
        [3u64, 5, 7].iter().any(|&b| is_power_of(group, b))
    }

    /// Volume byte offset of `block`, if it lies inside the filesystem.
    pub(super) fn block_offset(&self, block: u64) -> Option<u64> {
        (block < self.blocks_count).then(|| block * self.block_size)
    }

    pub(super) fn is_block(&self, block: u64) -> bool {
        block >= self.first_data_block && block < self.blocks_count
    }

}

fn is_power_of(mut n: u64, base: u64) -> bool {
    while n > 1 && n.is_multiple_of(base) {
        n /= base;
    }
    n == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_super_groups() {
        assert!(is_power_of(27, 3) && is_power_of(125, 5) && is_power_of(49, 7));
        assert!(!is_power_of(15, 3) && !is_power_of(0, 3));
    }
}
