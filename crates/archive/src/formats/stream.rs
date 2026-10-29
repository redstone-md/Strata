//! Single-stream compressors (GZIP, BZIP2, XZ): one member, the decompressed content.

use crate::codec;
use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use strata_kernel::bytes::{u32_le, u8_at};
use strata_kernel::{Error, Result, Timestamp};

pub(crate) struct StreamReader<'a> {
    format: ArchiveFormat,
    data: &'a [u8],
}

impl<'a> StreamReader<'a> {
    pub fn new(format: ArchiveFormat, data: &'a [u8]) -> Self {
        Self { format, data }
    }

    /// GZIP stores the original name and mtime; the others store nothing.
    fn gzip_meta(&self) -> (String, Option<Timestamp>) {
        let d = self.data;
        let flags = u8_at(d, 3).unwrap_or(0);
        let mtime = u32_le(d, 4).filter(|t| *t != 0).and_then(|t| Timestamp::from_unix_secs(i64::from(t)));
        let mut at = 10usize;
        if flags & 0x04 != 0 {
            at += 2 + usize::from(strata_kernel::bytes::u16_le(d, at).unwrap_or(0));
        }
        let name = if flags & 0x08 != 0 {
            let tail = d.get(at..).unwrap_or_default();
            let end = tail.iter().take(1024).position(|b| *b == 0).unwrap_or(0);
            String::from_utf8_lossy(&tail[..end]).into_owned()
        } else {
            String::new()
        };
        (name, mtime)
    }
}

impl ArchiveReader for StreamReader<'_> {
    fn format(&self) -> ArchiveFormat {
        self.format
    }

    /// One entry. An empty path means "name it after the container" (see the unpacker).
    fn entries(&self) -> Vec<ArchiveEntry> {
        let (name, mtime) = if self.format == ArchiveFormat::Gzip { self.gzip_meta() } else { (String::new(), None) };
        let mut e = ArchiveEntry::new(0, name);
        e.packed = Some(self.data.len() as u64);
        e.mtime = mtime;
        if self.format == ArchiveFormat::Gzip {
            // ISIZE (size mod 2^32) of the last member; only a hint.
            e.size = self.data.len().checked_sub(4).and_then(|p| u32_le(self.data, p)).map(u64::from);
        }
        vec![e]
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        if entry.index != 0 {
            return Err(Error::Other("stream has one member".into()));
        }
        let out = match self.format {
            ArchiveFormat::Gzip => codec::gzip(self.data, limit),
            ArchiveFormat::Bzip2 => codec::bzip2(self.data, limit),
            _ => codec::xz(self.data, limit),
        };
        if out.data.is_empty() && !out.damage.is_empty() {
            return Err(Error::Other(out.damage.iter().map(|d| d.note()).collect::<Vec<_>>().join("; ")));
        }
        Ok(out.into_parts())
    }
}
