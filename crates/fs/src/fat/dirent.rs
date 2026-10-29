//! Raw 32-byte directory entries: 8.3 entries and long-file-name slots.

use strata_kernel::Timestamp;
use strata_kernel::bytes::{array, u16_le, u32_le, u8_at};

pub(super) const ENTRY_SIZE: usize = 32;
pub(super) const DELETED_MARK: u8 = 0xE5;
const ATTR_VOLUME: u8 = 0x08;
const ATTR_DIR: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;
const CASE_LOWER_BASE: u8 = 0x08;
const CASE_LOWER_EXT: u8 = 0x10;
const FORBIDDEN: &[u8] = b"\"*+,./:;<=>?[\\]|";

/// Is this 32-byte slot a long-file-name fragment?
pub(super) fn is_lfn(e: &[u8]) -> bool {
    u8_at(e, 11).is_some_and(|a| a & 0x3F == ATTR_LFN) && u16_le(e, 26) == Some(0)
}

/// Checksum of an 8.3 name stored in every LFN slot.
pub(super) fn lfn_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, b| sum.rotate_right(1).wrapping_add(*b))
}

pub(super) struct LfnSlot {
    order: u8,
    checksum: u8,
    units: [u16; 13],
}

impl LfnSlot {
    pub(super) fn parse(e: &[u8]) -> Option<Self> {
        let mut units = [0u16; 13];
        let spans = [(1usize, 5usize), (14, 6), (28, 2)];
        let mut k = 0;
        for (start, n) in spans {
            for j in 0..n {
                units[k] = u16_le(e, start + 2 * j)?;
                k += 1;
            }
        }
        Some(Self { order: u8_at(e, 0)?, checksum: u8_at(e, 13)?, units })
    }

    pub(super) fn is_deleted(&self) -> bool {
        self.order == DELETED_MARK
    }

    pub(super) fn sequence(&self) -> u8 {
        self.order & 0x1F
    }

    pub(super) fn is_last(&self) -> bool {
        self.order & 0x40 != 0
    }

    pub(super) fn checksum(&self) -> u8 {
        self.checksum
    }

    /// Name from slots in on-disk order (last part first).
    pub(super) fn assemble(slots: &[LfnSlot]) -> String {
        let units: Vec<u16> =
            slots.iter().rev().flat_map(|s| s.units).take_while(|u| *u != 0).filter(|u| *u != 0xFFFF).collect();
        String::from_utf16_lossy(&units)
    }
}

pub(super) struct ShortEntry {
    name: [u8; 11],
    attr: u8,
    case: u8,
    cluster_hi: u16,
    cluster_lo: u16,
    size: u32,
    created: Option<Timestamp>,
    modified: Option<Timestamp>,
    accessed: Option<Timestamp>,
}

impl ShortEntry {
    pub(super) fn parse(e: &[u8]) -> Option<Self> {
        Some(Self {
            name: array(e, 0)?,
            attr: u8_at(e, 11)?,
            case: u8_at(e, 12)?,
            cluster_hi: u16_le(e, 20)?,
            cluster_lo: u16_le(e, 26)?,
            size: u32_le(e, 28)?,
            created: Timestamp::from_dos(u16_le(e, 16)?, u16_le(e, 14)?),
            modified: Timestamp::from_dos(u16_le(e, 24)?, u16_le(e, 22)?),
            accessed: Timestamp::from_dos(u16_le(e, 18)?, 0),
        })
    }

    pub(super) fn is_deleted(&self) -> bool {
        self.name[0] == DELETED_MARK
    }

    pub(super) fn is_dir(&self) -> bool {
        self.attr & ATTR_DIR != 0
    }

    pub(super) fn is_volume_label(&self) -> bool {
        self.attr & ATTR_VOLUME != 0 && !self.is_dir()
    }

    pub(super) fn is_dot(&self) -> bool {
        self.name[0] == b'.' && self.name[1..].iter().all(|b| *b == b' ' || *b == b'.')
    }

    /// `.` entry: the first slot of every subdirectory, pointing at the directory itself.
    pub(super) fn is_self_entry(&self, cluster: u32) -> bool {
        &self.name == b".          " && self.is_dir() && (self.cluster(true) == cluster || u32::from(self.cluster_lo) == cluster)
    }

    /// Characters a real 8.3 name can hold (first byte may be the deletion mark).
    pub(super) fn is_plausible(&self) -> bool {
        let valid = |b: &u8| *b >= 0x20 && !FORBIDDEN.contains(b) && !b.is_ascii_lowercase();
        self.name[0] != b' ' && self.name[1..].iter().all(valid) && (self.is_deleted() || self.name[0] == 0x05 || valid(&self.name[0]))
    }

    /// First cluster; FAT12/16 have no high word.
    pub(super) fn cluster(&self, fat32: bool) -> u32 {
        let hi = if fat32 { u32::from(self.cluster_hi) } else { 0 };
        (hi << 16) | u32::from(self.cluster_lo)
    }

    /// Low word only (some systems clear the high word when deleting on FAT32).
    pub(super) fn cluster_low(&self) -> u32 {
        u32::from(self.cluster_lo)
    }

    pub(super) fn size(&self) -> u32 {
        self.size
    }

    pub(super) fn times(&self) -> crate::FileTimes {
        crate::FileTimes { created: self.created, modified: self.modified, accessed: self.accessed, changed: None }
    }

    pub(super) fn checksum(&self) -> u8 {
        lfn_checksum(&self.name)
    }

    /// Checksum the name would have with `first` as its first byte (deleted entries).
    pub(super) fn checksum_with_first(&self, first: u8) -> u8 {
        let mut name = self.name;
        name[0] = first;
        lfn_checksum(&name)
    }

    /// `NAME.EXT`, honouring the NT lower-case flags. `first` replaces the first byte
    /// (deleted entries, whose first byte was overwritten by 0xE5).
    pub(super) fn display_name(&self, first: Option<u8>) -> String {
        let mut raw = self.name;
        match first {
            Some(b) => raw[0] = b,
            None if raw[0] == 0x05 => raw[0] = DELETED_MARK,
            None => {}
        }
        let part = |bytes: &[u8], lower: bool| -> String {
            let s: String = bytes.iter().map(|b| decode_oem(*b)).collect::<String>().trim_end().to_string();
            if lower { s.to_lowercase() } else { s }
        };
        let base = part(&raw[..8], self.case & CASE_LOWER_BASE != 0);
        let ext = part(&raw[8..], self.case & CASE_LOWER_EXT != 0);
        if ext.is_empty() { base } else { format!("{base}.{ext}") }
    }
}

/// OEM code page byte to char. ASCII as is, Cyrillic per CP866 (Russian Windows), else `_`.
pub(super) fn decode_oem(b: u8) -> char {
    let cp = match b {
        0x00..=0x7F => return char::from(b),
        0x80..=0xAF => 0x0410 + u32::from(b - 0x80),
        0xE0..=0xEF => 0x0440 + u32::from(b - 0xE0),
        0xF0 => 0x0401,
        0xF1 => 0x0451,
        _ => return '_',
    };
    char::from_u32(cp).unwrap_or('_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_reference() {
        // Reference value computed with the algorithm from the FAT specification.
        let name = *b"README  TXT";
        let mut sum = 0u8;
        for b in name {
            sum = (if sum & 1 != 0 { 0x80u8 } else { 0 }).wrapping_add(sum >> 1).wrapping_add(b);
        }
        assert_eq!(lfn_checksum(&name), sum);
    }

    #[test]
    fn oem_names_decode_cyrillic_and_case() {
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(b"\x8f\xe0\xa8\xac    TXT");
        e[12] = CASE_LOWER_EXT;
        let s = ShortEntry::parse(&e).unwrap();
        assert_eq!(s.display_name(None), "Прим.txt");
        assert!(s.is_plausible());
    }
}
