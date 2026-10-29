//! Microsoft cabinet via the `cab` crate (stored, MSZIP, LZX).

use crate::codec::{guarded, read_limited};
use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use std::cell::RefCell;
use std::io::Cursor;
use strata_kernel::{Error, Result, Timestamp};

pub(crate) struct CabReader<'a> {
    cab: RefCell<cab::Cabinet<Cursor<&'a [u8]>>>,
    entries: Vec<ArchiveEntry>,
    /// Names as stored (backslash-separated), for lookups.
    names: Vec<String>,
}

impl<'a> CabReader<'a> {
    pub fn open(data: &'a [u8]) -> Option<Self> {
        let cab = guarded("cab header", || cab::Cabinet::new(Cursor::new(data))).ok()?.ok()?;
        let (mut entries, mut names) = (Vec::new(), Vec::new());
        for folder in cab.folder_entries() {
            for f in folder.file_entries() {
                let mut e = ArchiveEntry::new(entries.len(), f.name());
                e.size = Some(u64::from(f.uncompressed_size()));
                e.mtime = f.datetime().and_then(|t| {
                    Timestamp::from_civil(
                        i64::from(t.year()),
                        i64::from(u8::from(t.month())),
                        i64::from(t.day()),
                        i64::from(t.hour()),
                        i64::from(t.minute()),
                        i64::from(t.second()),
                    )
                });
                entries.push(e);
                names.push(f.name().to_string());
            }
        }
        Some(Self { cab: RefCell::new(cab), entries, names })
    }
}

impl ArchiveReader for CabReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Cab
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        self.entries.clone()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        let name = self.names.get(entry.index).ok_or_else(|| Error::Other(format!("{}: no such member", entry.path)))?;
        let mut cab = self.cab.borrow_mut();
        let out = guarded("cab member", || match cab.read_file(name) {
            Ok(r) => Ok(read_limited(r, limit, &entry.path)),
            Err(e) => Err(Error::Other(format!("{}: {e}", entry.path))),
        })??;
        if out.data.is_empty() && !out.damage.is_empty() {
            return Err(Error::Other(out.damage.iter().map(|d| d.note()).collect::<Vec<_>>().join("; ")));
        }
        Ok(out.into_parts())
    }
}
