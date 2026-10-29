//! Values of `$STANDARD_INFORMATION`, `$FILE_NAME` and `$ATTRIBUTE_LIST`.

use super::record::FileRef;
use crate::FileTimes;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at, utf16le};

/// Four FILETIMEs in NTFS order: created, modified, MFT changed, accessed.
fn times_at(v: &[u8], off: usize) -> FileTimes {
    let at = |i: usize| u64_le(v, off + 8 * i).and_then(Timestamp::from_filetime);
    FileTimes { created: at(0), modified: at(1), changed: at(2), accessed: at(3) }
}

pub(super) fn standard_times(v: &[u8]) -> Option<FileTimes> {
    (v.len() >= 32).then(|| times_at(v, 0))
}

const NAMESPACE_DOS: u8 = 2;
const FN_FLAG_DIRECTORY: u32 = 0x1000_0000;

pub(super) struct FileName {
    parent: FileRef,
    times: FileTimes,
    name: String,
    namespace: u8,
    dir_flag: bool,
}

impl FileName {
    pub(super) fn parse(v: &[u8]) -> Option<Self> {
        let len = usize::from(u8_at(v, 0x40)?);
        let raw = v.get(0x42..0x42 + 2 * len)?;
        // Not `utf16le`: names may legally hold no NUL, but must not be cut at one either.
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let name = String::from_utf16_lossy(&units);
        if name.is_empty() {
            return None;
        }
        Some(Self {
            parent: FileRef::from_raw(u64_le(v, 0)?),
            times: times_at(v, 8),
            name,
            namespace: u8_at(v, 0x41)?,
            dir_flag: u32_le(v, 0x38).is_some_and(|f| f & FN_FLAG_DIRECTORY != 0),
        })
    }

    /// Lower is better: Win32 and POSIX names beat the 8.3 DOS alias.
    pub(super) fn rank(&self) -> u8 {
        u8::from(self.namespace == NAMESPACE_DOS)
    }

    pub(super) fn parent(&self) -> FileRef {
        self.parent
    }

    pub(super) fn times(&self) -> FileTimes {
        self.times
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn is_dir(&self) -> bool {
        self.dir_flag
    }
}

/// One `$ATTRIBUTE_LIST` entry: which record holds which attribute instance.
pub(super) struct ListEntry {
    type_code: u32,
    name: String,
    record: FileRef,
}

impl ListEntry {
    pub(super) fn parse_all(v: &[u8]) -> Vec<Self> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while let (Some(type_code), Some(len)) = (u32_le(v, off), u16_le(v, off + 4)) {
            let len = usize::from(len);
            if len < 0x1A || type_code == 0 || type_code == 0xFFFF_FFFF {
                break;
            }
            let name_len = v.get(off + 6).copied().map_or(0, usize::from);
            let name_off = v.get(off + 7).copied().map_or(0, usize::from);
            let name = v.get(off + name_off..off + name_off + 2 * name_len).map(utf16le).unwrap_or_default();
            if let Some(record) = u64_le(v, off + 0x10).map(FileRef::from_raw) {
                out.push(Self { type_code, name, record });
            }
            off += len;
        }
        out
    }

    pub(super) fn type_code(&self) -> u32 {
        self.type_code
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn record(&self) -> FileRef {
        self.record
    }
}
