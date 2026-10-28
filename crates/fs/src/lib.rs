//! Filesystem context: turns a volume into a tree of files, live and deleted.
//!
//! Every implementation produces the same [`FileEntry`] model and reads content through the
//! shared [`ExtentReader`], so the rest of Strata never cares which filesystem a file came from.

mod entry;
mod extent;
mod ownership;

pub use entry::{EntryState, FileEntry, FileId, FileTimes};
pub use extent::{Extent, ExtentReader};
pub use ownership::OwnershipIndex;

use std::sync::Arc;
use strata_kernel::{ByteRange, Damage, Result};
use strata_source::BlockSource;
use strata_volume::FsKind;

/// A parsed filesystem. Construction does the full walk (including deleted entries and
/// orphan records); queries are then cheap.
pub trait FileSystem: Send + Sync {
    fn kind(&self) -> FsKind;

    /// Volume the filesystem lives on.
    fn source(&self) -> &Arc<dyn BlockSource>;

    /// All entries: allocated, deleted, orphaned. Index = position used by [`FileId`].
    fn entries(&self) -> &[FileEntry];

    fn entry(&self, id: FileId) -> Option<&FileEntry> {
        self.entries().get(id.index())
    }

    /// Children of a directory (deleted children included).
    fn children(&self, dir: FileId) -> Vec<FileId> {
        self.entries().iter().enumerate().filter(|(_, e)| e.parent == Some(dir)).map(|(i, _)| FileId::new(i)).collect()
    }

    /// Volume byte ranges not allocated to any live file (where carving looks first).
    fn unallocated(&self) -> Vec<ByteRange>;

    /// Problems met while parsing the metadata itself.
    fn damage(&self) -> &[Damage];

    /// Read file content. Unrecoverable parts (overwritten clusters, bad sectors) read as zeros
    /// and are listed in the entry's damage.
    fn read(&self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let entry = self.entry(id).ok_or(strata_kernel::Error::Other(format!("no file {id:?}")))?;
        ExtentReader::new(self.source().as_ref(), entry).read(offset, buf)
    }
}

/// Open the right parser for `kind`. Returns `Err` only if nothing at all could be parsed.
pub fn open_filesystem(source: Arc<dyn BlockSource>, kind: FsKind) -> Result<Box<dyn FileSystem>> {
    let _ = &source;
    Err(strata_kernel::Error::format(format!("filesystem {kind:?} not supported yet")))
}
