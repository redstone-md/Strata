//! On-disk inode: type, size, links, times (with nanosecond/epoch extra bits), flags, the
//! 60-byte `i_block` area (block map, extent root, inline data or fast symlink target) and the
//! inline-data tail kept in the in-inode `system.data` extended attribute.

use crate::FileTimes;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{u16_le, u32_le, u8_at};

const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

const INDEX_FL: u32 = 0x1000;
const EXTENTS_FL: u32 = 0x8_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;

const IBLOCK: usize = 0x28;
pub(super) const IBLOCK_LEN: usize = 60;
const GOOD_OLD_SIZE: usize = 128;
const XATTR_MAGIC: u32 = 0xEA02_0000;
/// `system.` namespace index; inline data lives in `system.data`.
const XATTR_SYSTEM: u8 = 7;
const EXTENT_MAGIC: u16 = 0xF30A;

#[derive(Debug, Clone)]
pub(super) struct Inode {
    ino: u32,
    /// Volume offset of the on-disk inode.
    offset: u64,
    mode: u16,
    flags: u32,
    size: u64,
    links: u16,
    dtime: u32,
    generation: u32,
    times: FileTimes,
    iblock: [u8; IBLOCK_LEN],
    inline_tail: Option<Vec<u8>>,
}

impl Inode {
    /// `None` for slots that were never used (no mode, no times).
    pub(super) fn parse(raw: &[u8], ino: u32, offset: u64) -> Option<Self> {
        let mode = u16_le(raw, 0x00)?;
        let ctime = u32_le(raw, 0x0C)?;
        if mode == 0 && ctime == 0 {
            return None;
        }
        let extra = Self::extra_end(raw);
        let field = |off: usize| if off + 4 <= extra { u32_le(raw, off) } else { None };
        let times = FileTimes {
            accessed: decode_time(u32_le(raw, 0x08)?, field(0x8C)),
            changed: decode_time(ctime, field(0x84)),
            modified: decode_time(u32_le(raw, 0x10)?, field(0x88)),
            created: field(0x90).and_then(|s| decode_time(s, field(0x94))),
        };
        let iblock: [u8; IBLOCK_LEN] = strata_kernel::bytes::array(raw, IBLOCK)?;
        let flags = u32_le(raw, 0x20)?;
        let inline_tail = if flags & INLINE_DATA_FL != 0 { inline_xattr(raw, extra) } else { None };
        Some(Self {
            ino,
            offset,
            mode,
            flags,
            size: u64::from(u32_le(raw, 0x04)?) | u64::from(u32_le(raw, 0x6C)?) << 32,
            links: u16_le(raw, 0x1A)?,
            dtime: u32_le(raw, 0x14)?,
            generation: u32_le(raw, 0x64)?,
            times,
            iblock,
            inline_tail,
        })
    }

    /// End of the fixed part plus `i_extra_isize` (where in-inode xattrs begin).
    fn extra_end(raw: &[u8]) -> usize {
        if raw.len() <= GOOD_OLD_SIZE {
            return GOOD_OLD_SIZE;
        }
        let extra = u16_le(raw, GOOD_OLD_SIZE).map_or(0, usize::from);
        (GOOD_OLD_SIZE + extra).min(raw.len())
    }

    pub(super) fn ino(&self) -> u32 {
        self.ino
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn times(&self) -> FileTimes {
        self.times
    }

    pub(super) fn dtime(&self) -> Option<Timestamp> {
        decode_time(self.dtime, None)
    }

    pub(super) fn generation(&self) -> u32 {
        self.generation
    }

    pub(super) fn iblock(&self) -> &[u8; IBLOCK_LEN] {
        &self.iblock
    }

    pub(super) fn file_type(&self) -> u16 {
        self.mode & S_IFMT
    }

    pub(super) fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }

    pub(super) fn is_regular(&self) -> bool {
        self.file_type() == S_IFREG
    }

    /// Same file type as a directory entry's type byte (0 = unknown matches anything).
    pub(super) fn matches_dirent_type(&self, ftype: u8) -> bool {
        const TYPES: [u16; 8] = [0, S_IFREG, S_IFDIR, 0x2000, 0x6000, 0x1000, 0xC000, S_IFLNK];
        ftype == 0 || TYPES.get(usize::from(ftype)).is_none_or(|t| *t == self.file_type())
    }

    pub(super) fn uses_extents(&self) -> bool {
        self.flags & EXTENTS_FL != 0 && u16_le(&self.iblock, 0) == Some(EXTENT_MAGIC)
    }

    pub(super) fn is_htree(&self) -> bool {
        self.flags & INDEX_FL != 0
    }

    /// Unlinked: no names left, or a deletion time is recorded.
    pub(super) fn is_deleted(&self) -> bool {
        self.links == 0 || self.dtime != 0
    }

    pub(super) fn is_inline(&self) -> bool {
        self.flags & INLINE_DATA_FL != 0
    }

    /// Symlink whose target sits in `i_block` itself.
    pub(super) fn is_fast_symlink(&self) -> bool {
        self.file_type() == S_IFLNK && self.flags & (EXTENTS_FL | INLINE_DATA_FL) == 0 && self.size < IBLOCK_LEN as u64
    }

    /// Content stored in the inode itself (inline data, fast symlink target).
    pub(super) fn resident(&self) -> Option<Vec<u8>> {
        if !self.is_inline() && !self.is_fast_symlink() {
            return None;
        }
        let mut data = self.iblock.to_vec();
        if self.is_inline() {
            data.extend(self.inline_tail.iter().flatten());
        }
        data.truncate(usize::try_from(self.size).unwrap_or(usize::MAX));
        Some(data)
    }

    /// Volume offset of the on-disk inode.
    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    /// Volume offset of `i_block`, where resident content starts.
    pub(super) fn iblock_offset(&self) -> u64 {
        self.offset + IBLOCK as u64
    }

    /// Whether `i_block` still references any data (extent entries or block pointers).
    pub(super) fn has_pointers(&self) -> bool {
        if self.is_inline() || self.is_fast_symlink() {
            return false;
        }
        if self.uses_extents() {
            return u16_le(&self.iblock, 2).is_some_and(|n| n > 0);
        }
        self.iblock.iter().any(|b| *b != 0)
    }
}

/// Seconds plus the ext4 extra word: low 2 bits extend the epoch, the rest are nanoseconds.
fn decode_time(secs: u32, extra: Option<u32>) -> Option<Timestamp> {
    if secs == 0 && extra.unwrap_or(0) == 0 {
        return None;
    }
    let mut s = i64::from(secs as i32);
    let mut nanos = 0i64;
    if let Some(x) = extra {
        s += i64::from(x & 3) << 32;
        nanos = i64::from(x >> 2);
    }
    Timestamp::from_unix_micros(s.checked_mul(1_000_000)?.checked_add(nanos / 1000)?)
}

/// Value of the in-inode `system.data` attribute (inline data beyond the first 60 bytes).
fn inline_xattr(raw: &[u8], start: usize) -> Option<Vec<u8>> {
    if u32_le(raw, start)? != XATTR_MAGIC {
        return None;
    }
    let base = start + 4;
    let mut at = base;
    while at + 16 <= raw.len() && u32_le(raw, at)? != 0 {
        let name_len = usize::from(u8_at(raw, at)?);
        let index = u8_at(raw, at + 1)?;
        let value_off = usize::from(u16_le(raw, at + 2)?);
        let value_len = u32_le(raw, at + 8)? as usize;
        let name = raw.get(at + 16..at + 16 + name_len)?;
        if index == XATTR_SYSTEM && name == b"data" {
            return raw.get(base + value_off..base.checked_add(value_off)?.checked_add(value_len)?).map(<[u8]>::to_vec);
        }
        at += (16 + name_len).next_multiple_of(4);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_time_bits() {
        // 2020-01-01 00:00:00 + 500 ms; epoch bits 0.
        let t = decode_time(1_577_836_800, Some(500_000_000 << 2)).unwrap();
        assert_eq!(t.unix_micros(), 1_577_836_800_500_000);
        // Negative 32-bit seconds pushed past 2038 by the epoch bit.
        let t = decode_time(0x8000_0000, Some(1)).unwrap();
        assert_eq!(t.unix_secs(), 0x8000_0000);
        assert!(decode_time(0, None).is_none());
    }

    #[test]
    fn short_or_garbage_inodes_never_panic() {
        assert!(Inode::parse(&[0xFF; 40], 1, 0).is_none());
        let i = Inode::parse(&[0xFF; 256], 1, 0).unwrap();
        assert!(i.resident().is_some() || i.has_pointers() || !i.has_pointers());
    }
}
