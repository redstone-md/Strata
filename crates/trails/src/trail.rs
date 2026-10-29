//! A wallet trail: the chain of evidence about one wallet-relevant file, and the verdict on
//! where it is now.

use serde::{Deserialize, Serialize};
use strata_crypto::WalletNameKind;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::{Lead, LeadRef, LeadRule};

/// Where the file ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Fate {
    /// Still on a disk at the path the traces name.
    Live,
    /// Gone from that path, but the same file is elsewhere (copied, moved or renamed).
    Moved { live: bool },
    /// The file-table entry at that path is deleted. `verified`: its content was still read
    /// as a wallet or key, so the clusters were not reused.
    Deleted { verified: bool },
    /// Only inside an archive.
    InArchive,
    /// Only as a mail attachment.
    InMail,
    /// Only as bytes in free space (carved or found by a detector), no file entry.
    Carved,
    /// Only traces name it; no copy was found on any disk of the case.
    NotFound,
}

impl Fate {
    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Moved { live: true } => "moved or copied",
            Self::Moved { live: false } => "moved, copy deleted",
            Self::Deleted { verified: true } => "deleted, recoverable",
            Self::Deleted { verified: false } => "deleted, unverified",
            Self::InArchive => "in an archive",
            Self::InMail => "in mail",
            Self::Carved => "carved from free space",
            Self::NotFound => "not found",
        }
    }

    /// Lower is a better chance of getting the file back.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Live => 0,
            Self::Moved { live: true } => 1,
            Self::Deleted { verified: true } => 2,
            Self::InArchive => 3,
            Self::InMail => 4,
            Self::Moved { live: false } => 5,
            Self::Carved => 6,
            Self::Deleted { verified: false } => 7,
            Self::NotFound => 8,
        }
    }

    /// Lead score before confidence: how much an investigator gains by following the trail.
    pub(crate) fn weight(self) -> f32 {
        match self {
            Self::Deleted { verified: true } => 66.0,
            Self::Moved { live: true } => 62.0,
            Self::InArchive => 58.0,
            Self::Carved => 56.0,
            Self::InMail => 55.0,
            Self::Moved { live: false } => 52.0,
            Self::Deleted { verified: false } => 50.0,
            Self::NotFound => 48.0,
            Self::Live => 35.0,
        }
    }
}

/// The conclusion with its confidence (0..=1) and the sentences behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub fate: Fate,
    pub confidence: f32,
    pub explanation: Vec<String>,
}

/// What one step of a trail shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepKind {
    Installed,
    Downloaded,
    Ran,
    Created,
    Modified,
    Opened,
    Accessed,
    Loaded,
    Deleted,
    /// The file as it is now (live or deleted entry, its content read).
    Found,
    Archived,
    Mailed,
    Carved,
}

impl StepKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Downloaded => "downloaded",
            Self::Ran => "ran",
            Self::Created => "created",
            Self::Modified => "modified",
            Self::Opened => "opened",
            Self::Accessed => "accessed",
            Self::Loaded => "loaded",
            Self::Deleted => "deleted",
            Self::Found => "found",
            Self::Archived => "archived",
            Self::Mailed => "mailed",
            Self::Carved => "carved",
        }
    }
}

/// What a step links to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepLink {
    /// Stored timeline event.
    Event(i64),
    /// Stored finding.
    Hit { id: i64, category: HitCategory, value: String },
    /// A file-table entry (or an archive file for members).
    File { evidence: EvidenceId, volume: Option<u32>, path: String },
    /// Stored mail message, with its subject (what the mail list searches by).
    Message { id: i64, subject: String },
}

/// One link of the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrailStep {
    pub at: Option<Timestamp>,
    pub kind: StepKind,
    /// One plain sentence.
    pub text: String,
    pub evidence: EvidenceId,
    pub link: StepLink,
}

/// Everything known about one wallet-relevant file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trail {
    /// Stable across rebuilds: the path (or finding) it is about.
    pub id: String,
    /// `wallet.dat`.
    pub name: String,
    pub kind: Option<WalletNameKind>,
    /// The path the traces name, as first written.
    pub origin: String,
    pub verdict: Verdict,
    /// Oldest first; undated steps last.
    pub steps: Vec<TrailStep>,
    /// Where to look next (for files not found or not verified).
    pub hints: Vec<String>,
    /// 0..=100, comparable with lead scores.
    pub score: f32,
    pub window: Option<(Timestamp, Timestamp)>,
    pub evidence: Vec<EvidenceId>,
}

impl Trail {
    /// `wallet.dat — deleted, recoverable`.
    pub fn title(&self) -> String {
        format!("{} — {}", self.name, self.verdict.fate.label())
    }

    /// Stored findings the trail rests on.
    pub fn hits(&self) -> impl Iterator<Item = i64> + '_ {
        self.steps.iter().filter_map(|s| if let StepLink::Hit { id, .. } = s.link { Some(id) } else { None })
    }

    /// Stored timeline events the trail rests on.
    pub fn events(&self) -> impl Iterator<Item = i64> + '_ {
        self.steps.iter().filter_map(|s| if let StepLink::Event(id) = s.link { Some(id) } else { None })
    }

    /// The trail as a ranked lead, for the lead list and the connection map.
    pub fn to_lead(&self) -> Lead {
        let mut refs: Vec<LeadRef> = self.hits().map(LeadRef::Hit).chain(self.events().map(LeadRef::Event)).collect();
        refs.dedup();
        let mut explanation = self.verdict.explanation.clone();
        explanation.extend(self.hints.iter().cloned());
        Lead {
            id: format!("trail:{}", self.id),
            rule: LeadRule::WalletTrail,
            title: format!("{}: {}", self.name, self.verdict.fate.label()),
            explanation,
            score: self.score,
            refs,
            window: self.window,
            evidence: self.evidence.clone(),
        }
    }
}
