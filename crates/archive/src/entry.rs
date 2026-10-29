//! What a reader reports about one archive member.

use serde::{Deserialize, Serialize};
use strata_identify::TypeId;
use strata_kernel::{Damage, Timestamp};

/// Archive formats with a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Tar,
    SevenZip,
    Rar,
    Cab,
}

impl ArchiveFormat {
    /// The reader for an identified file type, if there is one.
    pub fn for_type(t: TypeId) -> Option<Self> {
        Some(match t {
            TypeId::Zip => Self::Zip,
            TypeId::Gzip => Self::Gzip,
            TypeId::Bzip2 => Self::Bzip2,
            TypeId::Xz => Self::Xz,
            TypeId::Tar => Self::Tar,
            TypeId::SevenZip => Self::SevenZip,
            TypeId::Rar4 | TypeId::Rar5 => Self::Rar,
            TypeId::Cab => Self::Cab,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Zip => "ZIP",
            Self::Gzip => "GZIP",
            Self::Bzip2 => "BZIP2",
            Self::Xz => "XZ",
            Self::Tar => "TAR",
            Self::SevenZip => "7z",
            Self::Rar => "RAR",
            Self::Cab => "CAB",
        }
    }
}

/// One member as listed by its archive. Sizes are what the archive declares (may be absent or
/// wrong in damaged archives).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    /// Reader-specific position; pass the entry back to the same reader.
    pub index: usize,
    /// Path inside the archive, `/`-separated.
    pub path: String,
    pub size: Option<u64>,
    pub packed: Option<u64>,
    pub encrypted: bool,
    pub is_dir: bool,
    pub mtime: Option<Timestamp>,
    pub damage: Vec<Damage>,
}

impl ArchiveEntry {
    pub fn new(index: usize, path: impl Into<String>) -> Self {
        Self {
            index,
            path: path.into().replace('\\', "/"),
            size: None,
            packed: None,
            encrypted: false,
            is_dir: false,
            mtime: None,
            damage: Vec::new(),
        }
    }

    /// Last path component.
    pub fn name(&self) -> &str {
        self.path.trim_end_matches('/').rsplit('/').next().unwrap_or(&self.path)
    }
}
