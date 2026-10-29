//! exFAT directory entry sets: File (0x85) + Stream Extension (0xC0) + File Name (0xC1)
//! entries, checksummed together. Deleted sets keep their bytes with the in-use bit cleared.

use crate::FileTimes;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{array, u8_at, u16_le, u32_le, u64_le};

pub(super) const ENTRY_SIZE: usize = 32;
pub(super) const IN_USE: u8 = 0x80;
pub(super) const TYPE_BITMAP: u8 = 0x81;
pub(super) const TYPE_LABEL: u8 = 0x83;
pub(super) const TYPE_FILE: u8 = 0x85;
pub(super) const TYPE_STREAM: u8 = 0xC0;
pub(super) const TYPE_NAME: u8 = 0xC1;
const ATTR_DIR: u16 = 0x10;
const FLAG_NO_FAT_CHAIN: u8 = 0x02;
const NAME_CHARS_PER_ENTRY: usize = 15;
/// File + Stream + at most 17 name entries (255 characters).
const MAX_SECONDARY: usize = 18;

/// One file or directory described by an entry set.
#[derive(Debug, Clone)]
pub(super) struct FileSet {
    name: String,
    attributes: u16,
    times: FileTimes,
    flags: u8,
    first_cluster: u32,
    data_length: u64,
    valid_length: u64,
    deleted: bool,
    checksum_ok: bool,
    complete: bool,
    entries: usize,
}

impl FileSet {
    /// Parse the set starting at `entries[0]` (a File entry, live or deleted). Returns `None`
    /// when not even the stream extension is there. `complete` is false when the set was cut
    /// short (overwritten or truncated name entries).
    pub(super) fn parse(entries: &[[u8; ENTRY_SIZE]]) -> Option<Self> {
        let file = entries.first()?;
        let deleted = file[0] & IN_USE == 0;
        let declared = usize::from(file[1]);
        if !(2..=MAX_SECONDARY).contains(&declared) {
            return None;
        }
        let in_state = |e: &[u8; ENTRY_SIZE], ty: u8| {
            if deleted { e[0] == ty & !IN_USE } else { e[0] == ty }
        };
        let stream = entries.get(1).filter(|e| in_state(e, TYPE_STREAM))?;
        let name_len = usize::from(u8_at(stream, 3)?);
        let names: Vec<&[u8; ENTRY_SIZE]> = entries.iter().skip(2).take(declared - 1).take_while(|e| in_state(e, TYPE_NAME)).collect();
        let needed = name_len.div_ceil(NAME_CHARS_PER_ENTRY);
        let units: Vec<u16> =
            names.iter().flat_map(|e| (0..NAME_CHARS_PER_ENTRY).filter_map(|i| u16_le(*e, 2 + 2 * i))).take(name_len).collect();
        // Secondary entries (category bit 0x40) in the same in-use state, vendor ones included.
        let secondaries = entries.iter().skip(1).take(declared).take_while(|e| e[0] & 0x40 != 0 && (e[0] & IN_USE == 0) == deleted).count();
        let present = 1 + secondaries;
        let complete = secondaries == declared && names.len() >= needed;
        let set_bytes: Vec<u8> = entries.iter().take(declared + 1).flatten().copied().collect();
        let stored = u16_le(file, 2)?;
        Some(Self {
            name: String::from_utf16_lossy(&units),
            attributes: u16_le(file, 4)?,
            times: times(file),
            flags: u8_at(stream, 1)?,
            first_cluster: u32_le(stream, 20)?,
            data_length: u64_le(stream, 24)?,
            valid_length: u64_le(stream, 8)?,
            deleted,
            checksum_ok: complete && set_checksum(&set_bytes, deleted) == stored,
            complete,
            entries: present,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn is_dir(&self) -> bool {
        self.attributes & ATTR_DIR != 0
    }

    pub(super) fn times(&self) -> FileTimes {
        self.times
    }

    pub(super) fn is_contiguous(&self) -> bool {
        self.flags & FLAG_NO_FAT_CHAIN != 0
    }

    pub(super) fn first_cluster(&self) -> u32 {
        self.first_cluster
    }

    pub(super) fn data_length(&self) -> u64 {
        self.data_length
    }

    /// Bytes actually written; the rest of the allocation reads as zeros.
    pub(super) fn valid_length(&self) -> u64 {
        self.valid_length.min(self.data_length)
    }

    pub(super) fn is_deleted(&self) -> bool {
        self.deleted
    }

    pub(super) fn checksum_ok(&self) -> bool {
        self.checksum_ok
    }

    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    /// How many 32-byte entries this set occupies.
    pub(super) fn entry_count(&self) -> usize {
        self.entries.max(1)
    }
}

/// Set checksum: rotate-right-and-add over every byte of the set except the checksum field.
/// Deleted sets are summed with their in-use bits restored, as they were when written.
pub(super) fn set_checksum(set: &[u8], deleted: bool) -> u16 {
    set.iter().enumerate().filter(|(i, _)| !matches!(i, 2 | 3)).fold(0u16, |sum, (i, b)| {
        let b = if deleted && i % ENTRY_SIZE == 0 { b | IN_USE } else { *b };
        sum.rotate_right(1).wrapping_add(u16::from(b))
    })
}

fn times(file: &[u8; ENTRY_SIZE]) -> FileTimes {
    let at = |ts: usize, ms: Option<usize>, utc: usize| {
        let stamp = u32_le(file, ts)?;
        let ms10 = ms.and_then(|m| u8_at(file, m)).unwrap_or(0);
        exfat_time(stamp, ms10, u8_at(file, utc)?)
    };
    FileTimes { created: at(8, Some(20), 22), modified: at(12, Some(21), 23), accessed: at(16, None, 24), changed: None }
}

/// exFAT timestamp: DOS date (high word) and time (low word), a 10 ms increment (0..199) and
/// an optional UTC offset in 15-minute steps. Returned as UTC when the offset is recorded,
/// otherwise as the local clock (like FAT).
pub(super) fn exfat_time(stamp: u32, ms10: u8, utc: u8) -> Option<Timestamp> {
    let base = Timestamp::from_dos((stamp >> 16) as u16, stamp as u16)?;
    let mut micros = base.unix_micros() + i64::from(ms10.min(199)) * 10_000;
    if utc & 0x80 != 0 {
        // 7-bit two's complement quarter hours east of UTC.
        let quarters = i64::from(((utc << 1) as i8) >> 1);
        micros -= quarters * 15 * 60 * 1_000_000;
    }
    Timestamp::from_unix_micros(micros)
}

/// Volume label entry: up to 11 UTF-16 characters.
pub(super) fn label(e: &[u8; ENTRY_SIZE]) -> Option<String> {
    let count = usize::from(u8_at(e, 1)?).min(11);
    let raw: [u8; 22] = array(e, 2)?;
    let units: Vec<u16> = raw.as_chunks::<2>().0.iter().take(count).map(|c| u16::from_le_bytes(*c)).collect();
    Some(String::from_utf16_lossy(&units)).filter(|s| !s.is_empty())
}

/// Allocation bitmap entry: (first cluster, length in bytes).
pub(super) fn bitmap(e: &[u8; ENTRY_SIZE]) -> Option<(u32, u64)> {
    Some((u32_le(e, 20)?, u64_le(e, 24)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_apply_increment_and_offset() {
        let date = ((2015u32 - 1980) << 9) | (6 << 5) | 1;
        let time = (12u32 << 11) | (30 << 5) | 5;
        let stamp = (date << 16) | time;
        assert_eq!(exfat_time(stamp, 0, 0).unwrap().to_string(), "2015-06-01 12:30:10");
        // +1.5 s and recorded at UTC+3 (12 quarters).
        let t = exfat_time(stamp, 150, 0x80 | 12).unwrap();
        assert_eq!(t.to_string(), "2015-06-01 09:30:11");
        assert_eq!(t.unix_micros() % 1_000_000, 500_000);
        // UTC-5 (-20 quarters as 7-bit two's complement).
        assert_eq!(exfat_time(stamp, 0, 0x80 | (128 - 20)).unwrap().to_string(), "2015-06-01 17:30:10");
        assert!(exfat_time(0, 0, 0).is_none());
    }
}
