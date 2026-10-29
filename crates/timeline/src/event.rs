use serde::{Deserialize, Serialize};
use strata_kernel::{Confidence, Timestamp};

/// What happened at an event's timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventKind {
    FileCreated,
    FileModified,
    FileAccessed,
    /// NTFS MFT-entry change time.
    MftChanged,
    FileDeleted,
    UrlVisited,
    Download,
    Search,
    ProgramRun,
    ProgramInstalled,
    DocumentOpened,
    UsbDevice,
    Login,
    AccountSeen,
    FormInput,
    Cookie,
    Email,
    WalletActivity,
    SystemLog,
    Other,
}

impl EventKind {
    pub const ALL: [EventKind; 20] = [
        Self::FileCreated,
        Self::FileModified,
        Self::FileAccessed,
        Self::MftChanged,
        Self::FileDeleted,
        Self::UrlVisited,
        Self::Download,
        Self::Search,
        Self::ProgramRun,
        Self::ProgramInstalled,
        Self::DocumentOpened,
        Self::UsbDevice,
        Self::Login,
        Self::AccountSeen,
        Self::FormInput,
        Self::Cookie,
        Self::Email,
        Self::WalletActivity,
        Self::SystemLog,
        Self::Other,
    ];

    /// Filesystem MACB events (usually the bulk of a timeline).
    pub fn is_filesystem(self) -> bool {
        matches!(self, Self::FileCreated | Self::FileModified | Self::FileAccessed | Self::MftChanged)
    }
}

/// Where an event was read from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventSource {
    /// Parser id, e.g. `chrome.history`, `registry.userassist`, `fs.ntfs`.
    pub artifact: String,
    /// Path of the evidence file (or a carve label).
    pub path: String,
    /// The evidence file itself was deleted / orphaned / recovered from free space.
    pub deleted: bool,
}

impl EventSource {
    pub fn new(artifact: impl Into<String>, path: impl Into<String>) -> Self {
        Self { artifact: artifact.into(), path: path.into(), deleted: false }
    }
}

/// One dated trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    at: Timestamp,
    kind: EventKind,
    title: String,
    detail: String,
    source: EventSource,
    actor: Option<String>,
    confidence: Confidence,
    tags: Vec<String>,
}

impl TimelineEvent {
    pub fn new(at: Timestamp, kind: EventKind, title: impl Into<String>, source: EventSource) -> Self {
        Self {
            at,
            kind,
            title: title.into(),
            detail: String::new(),
            source,
            actor: None,
            confidence: Confidence::HIGH,
            tags: Vec::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.set_actor(actor);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.add_tag(tag);
        self
    }

    pub fn at(&self) -> Timestamp {
        self.at
    }

    pub fn kind(&self) -> EventKind {
        self.kind
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn source(&self) -> &EventSource {
        &self.source
    }

    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }

    pub fn is_crypto(&self) -> bool {
        self.has_tag(crate::CRYPTO_TAG)
    }

    /// Adds a tag once (case-insensitive dedupe); empty tags are ignored.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !tag.is_empty() && !self.has_tag(&tag) {
            self.tags.push(tag);
        }
    }

    /// Sets the user profile; empty names are ignored.
    pub fn set_actor(&mut self, actor: impl Into<String>) {
        let actor = actor.into();
        if !actor.is_empty() {
            self.actor = Some(actor);
        }
    }

    /// Re-points the event at the evidence file it came from (used when a byte parser's result
    /// is attached to a filesystem entry or carve).
    pub fn set_origin(&mut self, path: &str, deleted: bool) {
        self.source.path = path.to_string();
        self.source.deleted |= deleted;
    }

    /// Case-insensitive match against title, detail, source path, actor and tags.
    pub fn matches_text(&self, needle_lower: &str) -> bool {
        let hit = |s: &str| s.to_lowercase().contains(needle_lower);
        hit(&self.title)
            || hit(&self.detail)
            || hit(&self.source.path)
            || self.actor.as_deref().is_some_and(hit)
            || self.tags.iter().any(|t| hit(t))
    }
}
