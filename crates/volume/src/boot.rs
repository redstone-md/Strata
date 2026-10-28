//! Boot-sector recognition shared by table parsing and lost-partition sweeps.

use serde::{Deserialize, Serialize};
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FsKind {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Unknown,
}

/// Recognised boot sector and the volume size it declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSector {
    pub kind: FsKind,
    pub declared_len: u64,
}

impl BootSector {
    pub fn parse(sector: &[u8]) -> Option<Self> {
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

    #[test]
    fn rejects_garbage() {
        assert!(BootSector::parse(&[0u8; 512]).is_none());
        assert!(BootSector::parse(&[0x55; 10]).is_none());
    }
}
