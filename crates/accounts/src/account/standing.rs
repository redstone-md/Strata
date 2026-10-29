use serde::{Deserialize, Serialize};

/// An address found only in places (a file, or one MiB of free space) that hold at least this
/// many distinct addresses is bulk: a dump, a mailing list, somebody's address book.
pub const BULK_PLACE_ADDRESSES: u32 = 50;

/// Whose account it likely is, as far as the traces tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Bulk addresses: only in dumps and lists (see [`BULK_PLACE_ADDRESSES`]).
    Bulk,
    /// The name only appears in data (pages, mail headers, free space).
    Seen,
    /// Some trace shows the account in use on this machine.
    Used,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bulk => "bulk",
            Self::Seen => "seen",
            Self::Used => "used",
        }
    }

    /// Stored rank (higher is closer to the owner).
    pub fn rank(self) -> i64 {
        match self {
            Self::Bulk => 0,
            Self::Seen => 1,
            Self::Used => 2,
        }
    }

    pub fn from_rank(rank: i64) -> Self {
        match rank {
            r if r >= 2 => Self::Used,
            1 => Self::Seen,
            _ => Self::Bulk,
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        [Self::Bulk, Self::Seen, Self::Used].into_iter().find(|s| s.label() == label.trim().to_ascii_lowercase())
    }
}
