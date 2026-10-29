//! Recognises volume structures at one sector-aligned position: boot sectors (and the
//! volumes their backups imply), ext superblocks (primary or backup), GPT headers and
//! MBR/EBR tables. Shared by the deep-scan detector and the add-time sweep.

use crate::boot::{BootSector, FsKind};
use crate::candidate::{Evidence, VolumeCandidate};
use crate::crc32::crc32;
use crate::mbr::{self, MbrEntry};
use serde::{Deserialize, Serialize};
use strata_kernel::bytes::{u16_le, u32_le, u64_le};

pub(crate) const SECTOR: u64 = 512;
const BOOT_SIG: [u8; 2] = [0x55, 0xAA];
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];
const GPT_MAGIC: &[u8; 8] = b"EFI PART";

/// A GPT header as found on the medium: enough to read its entry array later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptHeader {
    /// Absolute offset of LBA 0 of the disk this header describes.
    pub disk_start: u64,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
}

impl GptHeader {
    /// The header in the last sector (backup) rather than LBA 1.
    pub fn is_backup(&self) -> bool {
        self.my_lba > self.alternate_lba
    }
}

/// What one sector-aligned position holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Structure {
    Boot { boot: BootSector, backup_sector: Option<u64> },
    Superblock { boot: BootSector, group: u64, offset_in_volume: u64 },
    Gpt(GptHeader),
    Table(Vec<MbrEntry>),
}

impl Structure {
    /// Recognise the structure starting at `data[pos..]` (which sits at absolute `at`).
    pub fn at(data: &[u8], pos: usize, at: u64) -> Option<Self> {
        let s = data.get(pos..)?;
        if s.get(510..512) == Some(&BOOT_SIG) {
            let sector = s.get(..512)?;
            if let Some(boot) = BootSector::parse(sector) {
                return Some(Self::Boot { boot, backup_sector: backup_sector(sector, boot.kind) });
            }
            if let Some(entries) = mbr::strict_table(sector, at, SECTOR) {
                return Some(Self::Table(entries));
            }
        }
        if s.get(0x38..0x3A) == Some(&EXT_MAGIC) {
            return Self::superblock(s);
        }
        if s.get(..8) == Some(GPT_MAGIC) {
            return gpt_header(s, at).map(Self::Gpt);
        }
        None
    }

    fn superblock(sb: &[u8]) -> Option<Self> {
        // Beyond the shared validation: clean/error state, error policy and revision fields.
        let state = u16_le(sb, 0x3A)?;
        let errors = u16_le(sb, 0x3C)?;
        let rev = u32_le(sb, 0x4C)?;
        if !(1..=7).contains(&state) || !(1..=3).contains(&errors) || rev > 1 {
            return None;
        }
        let boot = BootSector::ext_superblock(sb)?;
        let group = u64::from(u16_le(sb, 0x5A)?);
        let block = 1024u64 << u32_le(sb, 0x18)?;
        let first_data_block = u64::from(u32_le(sb, 0x14)?);
        let per_group = u64::from(u32_le(sb, 0x20)?);
        let offset_in_volume = if group == 0 {
            1024
        } else {
            group.checked_mul(per_group)?.checked_add(first_data_block)?.checked_mul(block)?
        };
        Some(Self::Superblock { boot, group, offset_in_volume })
    }

    /// Volumes this structure implies when found at `at`. Several readings of one structure
    /// come back together; the caller decides which one holds up.
    pub fn candidates(&self, at: u64) -> Vec<VolumeCandidate> {
        match self {
            Self::Boot { boot, backup_sector } => {
                let mut out = Vec::new();
                out.extend(VolumeCandidate::behind(at, 0, boot.declared_len, boot.kind, Evidence::BootSector));
                let back = match boot.kind {
                    FsKind::Ntfs => boot.declared_len.checked_sub(SECTOR),
                    _ => backup_sector.map(|s| s * SECTOR),
                };
                out.extend(back.and_then(|b| VolumeCandidate::behind(at, b, boot.declared_len, boot.kind, Evidence::BackupBootSector)));
                out
            }
            Self::Superblock { boot, group, offset_in_volume } => {
                let evidence = if *group == 0 { Evidence::Superblock } else { Evidence::BackupSuperblock };
                VolumeCandidate::behind(at, *offset_in_volume, boot.declared_len, boot.kind, evidence).into_iter().collect()
            }
            Self::Gpt(_) => Vec::new(),
            Self::Table(entries) => entries
                .iter()
                .filter(|e| !mbr::is_extended(e.type_id))
                .map(|e| VolumeCandidate {
                    start: e.start,
                    len: e.len,
                    fs: mbr::type_hint(e.type_id),
                    evidence: Evidence::PartitionTable,
                    found_at: at,
                })
                .collect(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Boot { boot, .. } => format!("{} boot sector", boot.kind.name()),
            Self::Superblock { boot, group: 0, .. } => format!("{} superblock", boot.kind.name()),
            Self::Superblock { boot, group, .. } => format!("{} backup superblock (group {group})", boot.kind.name()),
            Self::Gpt(h) if h.is_backup() => "GPT backup header".into(),
            Self::Gpt(_) => "GPT header".into(),
            Self::Table(_) => "MBR/EBR partition table".into(),
        }
    }
}

/// Sector index of the backup copy a FAT32 or exFAT boot sector keeps.
fn backup_sector(s: &[u8], kind: FsKind) -> Option<u64> {
    match kind {
        FsKind::Fat32 => {
            let reserved = u16_le(s, 14)?;
            let bk = u16_le(s, 0x32)?;
            (bk > 0 && bk < reserved).then_some(u64::from(bk))
        }
        FsKind::ExFat => Some(12),
        _ => None,
    }
}

fn gpt_header(s: &[u8], at: u64) -> Option<GptHeader> {
    let size = u32_le(s, 12)? as usize;
    if !(92..=512).contains(&size) || u32_le(s, 8)? != 0x0001_0000 {
        return None;
    }
    let mut copy = s.get(..size)?.to_vec();
    copy.get_mut(16..20)?.fill(0);
    if crc32(&copy) != u32_le(s, 16)? {
        return None;
    }
    let my_lba = u64_le(s, 24)?;
    let entry_size = u32_le(s, 84)?;
    let entry_count = u32_le(s, 80)?;
    if !(128..=4096).contains(&entry_size) || entry_count == 0 || entry_count > 4096 {
        return None;
    }
    Some(GptHeader {
        disk_start: at.checked_sub(my_lba.checked_mul(SECTOR)?)?,
        my_lba,
        alternate_lba: u64_le(s, 32)?,
        entries_lba: u64_le(s, 72)?,
        entry_count,
        entry_size,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::boot::tests::{ext_head, ntfs_boot};

    #[test]
    fn ntfs_boot_reads_as_first_or_last_sector() {
        let s = ntfs_boot(2048);
        let st = Structure::at(&s, 0, 10 << 20).unwrap();
        let c = st.candidates(10 << 20);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].start, c[0].evidence), (10 << 20, Evidence::BootSector));
        assert_eq!((c[1].start, c[1].evidence), ((10 << 20) + 512 - 2048 * 512, Evidence::BackupBootSector));
    }

    /// The superblock part of [`ext_head`] with the state fields a mounted volume has.
    pub(crate) fn superblock(blocks: u64) -> Vec<u8> {
        let mut sb = ext_head(blocks, 0x4, 0x2)[1024..].to_vec();
        sb[0x3A] = 1;
        sb[0x3C] = 1;
        sb
    }

    #[test]
    fn superblock_primary_and_backup() {
        let mut sb = superblock(256);
        let st = Structure::at(&sb, 0, 5 << 20).unwrap();
        assert_eq!(st.candidates(5 << 20)[0].start, (5 << 20) - 1024);
        // Group 1 of a 4 KiB-block volume with 32768 blocks per group.
        sb[0x5A] = 1;
        let st = Structure::at(&sb, 0, 300 << 20).unwrap();
        let c = st.candidates(300 << 20)[0];
        assert_eq!((c.start, c.evidence), ((300 << 20) - 32768 * 4096, Evidence::BackupSuperblock));
        // Without a sane state field it is not taken.
        sb[0x3A] = 0;
        assert!(Structure::at(&sb, 0, 0).is_none());
    }

    #[test]
    fn gpt_header_needs_a_valid_crc() {
        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(GPT_MAGIC);
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&1u64.to_le_bytes());
        h[32..40].copy_from_slice(&999u64.to_le_bytes());
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        let crc = crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        let Some(Structure::Gpt(g)) = Structure::at(&h, 0, 4096 + 512) else { panic!("gpt") };
        assert_eq!((g.disk_start, g.is_backup()), (4096, false));
        h[100] = 1; // beyond the header size: still fine
        assert!(Structure::at(&h, 0, 512).is_some());
        h[40] ^= 1;
        assert!(Structure::at(&h, 0, 512).is_none());
    }

    #[test]
    fn random_sectors_are_not_structures() {
        let mut s = vec![0u8; 1024];
        s[510] = 0x55;
        s[511] = 0xAA;
        assert!(Structure::at(&s, 0, 0).is_none(), "empty table");
        s[446] = 0x33; // bad status byte
        s[446 + 4] = 7;
        s[446 + 8] = 1;
        s[446 + 12] = 1;
        assert!(Structure::at(&s, 0, 0).is_none());
        s[446] = 0x80;
        assert!(matches!(Structure::at(&s, 0, 0), Some(Structure::Table(_))));
    }
}
