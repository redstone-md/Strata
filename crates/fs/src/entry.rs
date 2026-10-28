use crate::Extent;
use serde::{Deserialize, Serialize};
use strata_kernel::{Damage, Timestamp};

/// Index of an entry inside its filesystem's entry list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileId(u32);

impl FileId {
    pub fn new(index: usize) -> Self {
        Self(u32::try_from(index).unwrap_or(u32::MAX))
    }

    pub fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryState {
    Allocated,
    /// Directory entry / MFT record marked free but still present.
    Deleted,
    /// Record found whose parent chain is gone (shown under a virtual `$Orphans` folder).
    Orphan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTimes {
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    pub accessed: Option<Timestamp>,
    /// NTFS MFT-entry change time.
    pub changed: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    /// Full path from the root, `/`-separated. Orphans start with `$Orphans/`.
    pub path: String,
    pub parent: Option<crate::FileId>,
    pub is_dir: bool,
    pub size: u64,
    pub state: EntryState,
    pub times: FileTimes,
    /// Where the content lives on the volume. Empty for resident/empty files.
    pub extents: Vec<Extent>,
    /// Small files stored inside metadata (NTFS resident $DATA).
    pub resident: Option<Vec<u8>>,
    /// Filesystem-native id (MFT record number, directory-entry byte offset).
    pub native_id: u64,
    /// Alternate data streams and similar named content (`name:stream`).
    pub streams: Vec<(String, Vec<Extent>, u64)>,
    pub damage: Vec<Damage>,
}

impl FileEntry {
    pub fn extension(&self) -> Option<&str> {
        let (stem, ext) = self.name.rsplit_once('.')?;
        (!stem.is_empty() && !ext.is_empty() && ext.len() <= 8).then_some(ext)
    }

    pub fn is_deleted(&self) -> bool {
        self.state != EntryState::Allocated
    }
}
