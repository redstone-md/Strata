//! Boot-sector recognition shared by table parsing and lost-partition sweeps.
//!
//! The detector looks at the first [`BootSector::HEAD_LEN`] bytes of a candidate volume: a DOS
//! boot sector (NTFS, exFAT, FAT) in sector 0, or an ext2/3/4 superblock at byte 1024.

use serde::{Deserialize, Serialize};
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FsKind {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ext2,
    Ext3,
    Ext4,
    Unknown,
}

impl FsKind {
    /// Name as people write it: `NTFS`, `FAT32`, `exFAT`, `ext4`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ntfs => "NTFS",
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
            Self::ExFat => "exFAT",
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Unknown => "Unknown filesystem",
        }
    }
}

/// Recognised boot sector and the volume size it declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    pub kind: FsKind,
    pub declared_len: u64,
}

/// ext superblock offset inside the volume, and the fields the detector checks.
const EXT_SB_OFFSET: usize = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const EXT_COMPAT_HAS_JOURNAL: u32 = 0x4;
/// EXTENTS | 64BIT | MMP | FLEX_BG | INLINE_DATA.
const EXT_INCOMPAT_EXT4: u32 = 0x40 | 0x80 | 0x100 | 0x200 | 0x8000;
const EXT_INCOMPAT_64BIT: u32 = 0x80;
/// HUGE_FILE | GDT_CSUM | DIR_NLINK | METADATA_CSUM.
const EXT_RO_COMPAT_EXT4: u32 = 0x8 | 0x10 | 0x20 | 0x400;

impl BootSector {
    /// Bytes from the volume start the detector needs (boot sector + ext superblock).
    pub const HEAD_LEN: usize = 2048;

    /// Recognise a volume from its first bytes (up to [`Self::HEAD_LEN`]; shorter input only
    /// checks what is present).
    pub fn parse(head: &[u8]) -> Option<Self> {
        Self::parse_boot(head).or_else(|| Self::ext_superblock(head.get(EXT_SB_OFFSET..)?))
    }

    /// Validate an ext2/3/4 superblock (the 1024 bytes at volume offset 1024 or a backup copy)
    /// and classify it. Shared with the filesystem parser so the rules live in one place.
    pub fn ext_superblock(sb: &[u8]) -> Option<Self> {
        if u16_le(sb, 0x38)? != EXT_MAGIC {
            return None;
        }
        let inodes = u32_le(sb, 0x00)?;
        let blocks_lo = u32_le(sb, 0x04)?;
        let log_block = u32_le(sb, 0x18)?;
        let blocks_per_group = u32_le(sb, 0x20)?;
        let inodes_per_group = u32_le(sb, 0x28)?;
        if log_block > 6 {
            return None;
        }
        let block = 1024u64 << log_block;
        let bits = block * 8;
        let sane = inodes > 0
            && blocks_lo > 0
            && (1..=bits).contains(&u64::from(blocks_per_group))
            && (1..=bits).contains(&u64::from(inodes_per_group))
            && inodes_per_group <= inodes;
        if !sane {
            return None;
        }
        let compat = u32_le(sb, 0x5C)?;
        let incompat = u32_le(sb, 0x60)?;
        let ro_compat = u32_le(sb, 0x64)?;
        let hi = if incompat & EXT_INCOMPAT_64BIT != 0 { u64::from(u32_le(sb, 0x150)?) } else { 0 };
        let blocks = (hi << 32) | u64::from(blocks_lo);
        let kind = if incompat & EXT_INCOMPAT_EXT4 != 0 || ro_compat & EXT_RO_COMPAT_EXT4 != 0 {
            FsKind::Ext4
        } else if compat & EXT_COMPAT_HAS_JOURNAL != 0 {
            FsKind::Ext3
        } else {
            FsKind::Ext2
        };
        Some(Self { kind, declared_len: blocks.checked_mul(block)? })
    }

    fn parse_boot(sector: &[u8]) -> Option<Self> {
        if sector.get(510..512)? != [0x55, 0xAA] {
            return None;
        }
        let oem = sector.get(3..11)?;
        if oem == b"NTFS    " {
            let bps = u64::from(u16_le(sector, 11)?);
            let total = u64_le(sector, 0x28)?;
            return Some(Self { kind: FsKind::Ntfs, declared_len: (total + 1) * bps });
        }
        if oem == b"EXFAT   " {
            let shift = u8_at(sector, 108)?;
            let total = u64_le(sector, 72)?;
            return (shift < 13).then_some(Self { kind: FsKind::ExFat, declared_len: total << shift });
        }
        Self::parse_fat(sector)
    }

    fn parse_fat(s: &[u8]) -> Option<Self> {
        let bps = u32::from(u16_le(s, 11)?);
        let spc = u32::from(u8_at(s, 13)?);
        let reserved = u32::from(u16_le(s, 14)?);
        let fats = u32::from(u8_at(s, 16)?);
        let root_entries = u32::from(u16_le(s, 17)?);
        let total16 = u32::from(u16_le(s, 19)?);
        let fat16 = u32::from(u16_le(s, 22)?);
        let total32 = u32_le(s, 32)?;
        let fat32 = u32_le(s, 36)?;
        let valid = matches!(bps, 512 | 1024 | 2048 | 4096)
            && spc.is_power_of_two()
            && spc <= 128
            && reserved > 0
            && (1..=2).contains(&fats)
            && matches!(u8_at(s, 21)?, 0xF0 | 0xF8..=0xFF);
        if !valid {
            return None;
        }
        let total = if total16 != 0 { total16 } else { total32 };
        let fat_size = if fat16 != 0 { fat16 } else { fat32 };
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let data = total.checked_sub(reserved + fats * fat_size + root_sectors)?;
        let clusters = data / spc;
        let kind = match clusters {
            0..4085 => FsKind::Fat12,
            4085..65525 => FsKind::Fat16,
            _ => FsKind::Fat32,
        };
        Some(Self { kind, declared_len: u64::from(total) * u64::from(bps) })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn ntfs_boot(total_sectors: u64) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[3..11].copy_from_slice(b"NTFS    ");
        s[11..13].copy_from_slice(&512u16.to_le_bytes());
        s[0x28..0x30].copy_from_slice(&(total_sectors - 1).to_le_bytes());
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn recognises_ntfs() {
        let b = BootSector::parse(&ntfs_boot(2048)).unwrap();
        assert_eq!(b, BootSector { kind: FsKind::Ntfs, declared_len: 2048 * 512 });
    }

    /// First 2 KiB of an ext volume: 4 KiB blocks, `blocks` blocks, given feature words.
    pub fn ext_head(blocks: u64, compat: u32, incompat: u32) -> Vec<u8> {
        let mut h = vec![0u8; BootSector::HEAD_LEN];
        let sb = &mut h[1024..];
        sb[0..4].copy_from_slice(&8192u32.to_le_bytes());
        sb[4..8].copy_from_slice(&(blocks as u32).to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192u32.to_le_bytes());
        sb[0x38..0x3A].copy_from_slice(&EXT_MAGIC.to_le_bytes());
        sb[0x5C..0x60].copy_from_slice(&compat.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        sb[0x150..0x154].copy_from_slice(&((blocks >> 32) as u32).to_le_bytes());
        h
    }

    #[test]
    fn recognises_ext_flavours() {
        let ext2 = BootSector::parse(&ext_head(1000, 0, 0x2)).unwrap();
        assert_eq!(ext2, BootSector { kind: FsKind::Ext2, declared_len: 1000 * 4096 });
        assert_eq!(BootSector::parse(&ext_head(1000, 0x4, 0x2)).unwrap().kind, FsKind::Ext3);
        let big = BootSector::parse(&ext_head((1 << 32) + 5, 0x4, 0x2C6)).unwrap();
        assert_eq!(big, BootSector { kind: FsKind::Ext4, declared_len: ((1 << 32) + 5) * 4096 });
        // Without INCOMPAT_64BIT the high word is ignored.
        let lo = BootSector::parse(&ext_head((1 << 32) + 5, 0x4, 0x40)).unwrap();
        assert_eq!(lo.declared_len, 5 * 4096);
    }

    #[test]
    fn rejects_insane_ext_superblocks() {
        let mut h = ext_head(1000, 0, 0);
        h[1024 + 0x18] = 9;
        assert!(BootSector::parse(&h).is_none());
        let mut h = ext_head(1000, 0, 0);
        h[1024 + 0x28..1024 + 0x2C].fill(0);
        assert!(BootSector::parse(&h).is_none());
        assert!(BootSector::parse(&ext_head(1000, 0, 0)[..1100]).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(BootSector::parse(&[0u8; 512]).is_none());
        assert!(BootSector::parse(&[0u8; 2048]).is_none());
        assert!(BootSector::parse(&[0x55; 10]).is_none());
    }
}
