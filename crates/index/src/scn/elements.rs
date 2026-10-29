//! Fixed-size scan elements: progress marks and recognised boot sectors.
//!
//! ```text
//! OOGR payload        u64 0 | u64 bytes scanned so far
//! TN/3 (NTFS boot)    48-byte records: u32 cluster | u32 MFT record | u64 $MFT offset
//!                     | u64 $MFTMirr offset | u32 index record | u32 sector | u64 volume size
//!                     | u64 absolute offset of the boot sector
//! AF/3 (FAT boot)     80-byte records: u32 FAT width (12/16/32) | ... | u64 absolute offset
//!                     of the boot sector at +72 (fields between are layout values not used)
//! ```
//! An NTFS boot record may be the primary (volume starts there) or the backup in the last
//! sector (volume starts `volume size` earlier); both readings are offered and our own
//! boot-sector check decides.

use crate::side::{BootRecord, EntrySource};
use strata_kernel::bytes::{u32_le, u64_le};
use strata_volume::FsKind;

const NTFS_RECORD: usize = 48;
const FAT_RECORD: usize = 80;
const FAT_OFFSET_AT: usize = 72;

/// Bytes scanned according to one progress group.
pub(crate) fn progress(payload: &[u8]) -> Option<u64> {
    u64_le(payload, 8)
}

/// Boot records from an NTFS element group.
pub(crate) fn ntfs_boot_records(payload: &[u8], disk_len: Option<u64>) -> Vec<BootRecord> {
    let mut out = Vec::new();
    for r in payload.as_chunks::<NTFS_RECORD>().0 {
        let (Some(size), Some(at), Some(sector)) = (u64_le(r, 32), u64_le(r, 40), u32_le(r, 28)) else { continue };
        if size == 0 || !matches!(sector, 512 | 1024 | 2048 | 4096) || disk_len.is_some_and(|d| at >= d) {
            continue;
        }
        let record = |start| BootRecord { found_at: at, volume_start: start, declared_len: size + u64::from(sector), fs: FsKind::Ntfs, source: EntrySource::RStudio };
        out.push(record(at));
        if let Some(start) = at.checked_sub(size) {
            out.push(record(start));
        }
    }
    out
}

/// Boot records from a FAT element group (length unknown until verified: 0).
pub(crate) fn fat_boot_records(payload: &[u8], disk_len: Option<u64>) -> Vec<BootRecord> {
    payload
        .as_chunks::<FAT_RECORD>()
        .0
        .iter()
        .filter_map(|r| {
            let fs = match u32_le(r, 0)? {
                12 => FsKind::Fat12,
                16 => FsKind::Fat16,
                32 => FsKind::Fat32,
                _ => return None,
            };
            let at = u64_le(r, FAT_OFFSET_AT)?;
            (disk_len.is_none_or(|d| at < d)).then_some(BootRecord { found_at: at, volume_start: at, declared_len: 0, fs, source: EntrySource::RStudio })
        })
        .collect()
}

/// Filesystem kind from R-Studio's filesystem name (`RCFS 0x01`).
pub(crate) fn fs_from_name(name: &str) -> FsKind {
    match name.to_ascii_lowercase().as_str() {
        "ntfs" => FsKind::Ntfs,
        "fat12" => FsKind::Fat12,
        "fat16" | "fat" => FsKind::Fat16,
        "fat32" => FsKind::Fat32,
        "exfat" => FsKind::ExFat,
        "ext2" => FsKind::Ext2,
        "ext3" => FsKind::Ext3,
        "ext4" => FsKind::Ext4,
        _ => FsKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scn::testkit::{fat_record, ntfs_record};

    #[test]
    fn ntfs_records_offer_primary_and_backup_readings() {
        let mut payload = ntfs_record(0x10_0000, 0x4000_0000 - 512, 512);
        payload.extend(ntfs_record(0x10_0000 + 0x4000_0000 - 512, 0x4000_0000 - 512, 512));
        payload.extend(ntfs_record(5, 99, 3));
        let r = ntfs_boot_records(&payload, Some(1 << 40));
        let starts: Vec<u64> = r.iter().map(|b| b.volume_start).collect();
        assert_eq!(starts, vec![0x10_0000, 0x10_0000 + 0x4000_0000 - 512, 0x10_0000]);
        assert!(r.iter().all(|b| b.fs == FsKind::Ntfs && b.declared_len == 0x4000_0000));
        assert!(ntfs_boot_records(&payload, Some(0x1000)).is_empty());
    }

    #[test]
    fn fat_records_and_names() {
        let mut payload = fat_record(32, 0x8000);
        payload.extend(fat_record(7, 0x9000));
        let r = fat_boot_records(&payload, None);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].fs, r[0].volume_start), (FsKind::Fat32, 0x8000));
        assert_eq!(fs_from_name("FAT32"), FsKind::Fat32);
        assert_eq!(fs_from_name("Ext4"), FsKind::Ext4);
        assert_eq!(fs_from_name("HFS+"), FsKind::Unknown);
        assert_eq!(progress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0]), Some(0x1000));
    }
}
