//! Directory content: 32-byte entries grouped into entry sets and the critical primaries
//! (allocation bitmap, volume label) found in the root.

use super::entry::{self, ENTRY_SIZE, FileSet, IN_USE, TYPE_BITMAP, TYPE_FILE, TYPE_LABEL};
use crate::dirbuf::DirBuffer;

/// A file entry set with the volume offset of its File entry.
pub(super) struct Record {
    set: FileSet,
    offset: u64,
}

impl Record {
    pub(super) fn set(&self) -> &FileSet {
        &self.set
    }

    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    /// Bytes the whole set spans on disk (for damage ranges).
    pub(super) fn span(&self) -> u64 {
        (self.set.entry_count() * ENTRY_SIZE) as u64
    }
}

#[derive(Default)]
pub(super) struct Listing {
    pub(super) records: Vec<Record>,
    pub(super) bitmap: Option<(u32, u64)>,
    pub(super) label: Option<String>,
}

/// Parse a directory up to its end-of-directory marker. Garbage entries are skipped.
pub(super) fn parse(buf: &DirBuffer) -> Listing {
    let entries = buf.bytes().as_chunks::<ENTRY_SIZE>().0;
    let mut out = Listing::default();
    let mut i = 0;
    while let Some(e) = entries.get(i) {
        let step = match e[0] {
            0x00 => break,
            t if t & !IN_USE == TYPE_FILE & !IN_USE => match FileSet::parse(&entries[i..]) {
                Some(set) => {
                    let n = set.entry_count();
                    out.records.push(Record { set, offset: buf.volume_offset(i * ENTRY_SIZE) });
                    n
                }
                None => 1,
            },
            TYPE_BITMAP => {
                // The first bitmap entry is the one in use (the second belongs to TexFAT).
                out.bitmap = out.bitmap.or_else(|| entry::bitmap(e));
                1
            }
            TYPE_LABEL => {
                out.label = entry::label(e);
                1
            }
            _ => 1,
        };
        i += step;
    }
    out
}
