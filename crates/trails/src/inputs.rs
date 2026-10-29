//! What the trail builder reads from a case: timeline events, wallet-relevant file entries,
//! wallet and key findings, archive members and mail attachments. Plain records; the case
//! context fills them, tests build them by hand.

use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::EventRecord;

/// State of a file-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EntryState {
    Live,
    Deleted,
    /// Found without a parent folder (deleted, its folder gone too).
    Orphan,
}

impl EntryState {
    /// From the stored spelling (`Allocated`, `Deleted`, `Orphan`).
    pub fn from_stored(s: &str) -> Self {
        match s {
            "Allocated" => Self::Live,
            "Orphan" => Self::Orphan,
            _ => Self::Deleted,
        }
    }

    pub fn is_live(self) -> bool {
        self == Self::Live
    }

    pub fn word(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Deleted => "deleted",
            Self::Orphan => "orphaned",
        }
    }
}

/// One entry of a file table (live, deleted or orphaned).
#[derive(Debug, Clone, PartialEq)]
pub struct FileRecord {
    pub evidence: EvidenceId,
    pub volume: u32,
    /// Path as stored, relative to its volume.
    pub path: String,
    pub size: u64,
    pub state: EntryState,
    pub created: Option<Timestamp>,
    pub modified: Option<Timestamp>,
    /// Metadata change (on NTFS close to the deletion of a deleted entry).
    pub changed: Option<Timestamp>,
    pub sha256: Option<String>,
    pub detected_type: Option<String>,
}

impl FileRecord {
    pub fn name(&self) -> &str {
        self.path.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or(&self.path)
    }
}

/// A wallet, key or seed finding.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletHit {
    pub id: i64,
    pub evidence: EvidenceId,
    pub category: HitCategory,
    pub detector: String,
    /// Detector label (`Bitcoin Core wallet (encrypted)`, `Berkeley DB file`).
    pub label: String,
    pub value: String,
    /// Disk offset.
    pub offset: u64,
    pub volume: Option<u32>,
    /// File the finding sits in (`archive.zip!/member` inside archives); `None` in free space.
    pub file_path: Option<String>,
    pub file_state: Option<EntryState>,
    pub confidence: f32,
    /// Addresses the wallet lists or the key derives.
    pub addresses: Vec<String>,
    /// Crack hash or another digest that is the same for copies of one wallet.
    pub fingerprint: Option<String>,
    /// Size of the file the finding stands for (a carved database's estimated size).
    pub size: Option<u64>,
    /// Wallet records or keys were read from it (not just a database header).
    pub has_records: bool,
}

impl WalletHit {
    /// A finding in free space, not inside any file.
    pub fn is_free(&self) -> bool {
        self.file_path.is_none()
    }

    /// Strong enough to stand as a trail on its own.
    pub fn stands_alone(&self) -> bool {
        match self.category {
            HitCategory::Wallet => self.has_records || self.confidence >= 0.5,
            _ => self.confidence >= 0.8,
        }
    }
}

/// A member of an archive found on a disk.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveMember {
    pub evidence: EvidenceId,
    pub archive_path: String,
    /// `archive!/dir/file`.
    pub member_path: String,
    pub size: Option<u64>,
    pub modified: Option<Timestamp>,
    pub encrypted: bool,
}

/// A file attached to a stored mail message.
#[derive(Debug, Clone, PartialEq)]
pub struct MailAttachment {
    pub message: i64,
    pub evidence: EvidenceId,
    pub name: String,
    pub size: u64,
    pub at: Option<Timestamp>,
    pub subject: String,
    pub sender: String,
}

/// Everything the builder links.
#[derive(Debug, Clone, Default)]
pub struct TrailInputs {
    pub events: Vec<EventRecord>,
    pub files: Vec<FileRecord>,
    pub hits: Vec<WalletHit>,
    pub members: Vec<ArchiveMember>,
    pub attachments: Vec<MailAttachment>,
}
