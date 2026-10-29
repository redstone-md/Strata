//! Accounts: who the user was on which service. An [`Account`] is the merged view of every
//! trace naming the same identifier on the same service, across artefacts, byte hits,
//! events and disks. Built by [`AccountResolver`].

mod resolver;

pub use resolver::AccountResolver;

use crate::catalogue::ServiceKind;
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Timestamp};

/// What an account identifier is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentifierKind {
    Email,
    Login,
    UserId,
    Nickname,
    Phone,
}

impl IdentifierKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Email => "e-mail",
            Self::Login => "login",
            Self::UserId => "user id",
            Self::Nickname => "nickname",
            Self::Phone => "phone",
        }
    }

    /// Kind from a free-form label (`e-mail (artefact)`, `login`, `Nickname`).
    pub fn from_label(label: &str) -> Self {
        let l = label.to_ascii_lowercase();
        if l.contains("mail") {
            Self::Email
        } else if l.contains("phone") {
            Self::Phone
        } else if l.contains("id") && !l.contains("ident") {
            Self::UserId
        } else if l.contains("nick") {
            Self::Nickname
        } else {
            Self::Login
        }
    }

    /// Which kind wins when two traces of one account disagree.
    fn strength(self) -> u8 {
        match self {
            Self::Email => 4,
            Self::Login => 3,
            Self::UserId => 2,
            Self::Nickname => 1,
            Self::Phone => 0,
        }
    }
}

/// Where a trace of an account was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceRef {
    /// A stored finding (hit row id).
    Hit(i64),
    /// A stored timeline event (event row id).
    Event(i64),
    /// A file path when no row exists.
    File(String),
}

/// One piece of evidence for an account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountSource {
    pub evidence: EvidenceId,
    pub origin: SourceRef,
    /// How the trace names the account (`saved browser login`, `URL ?login=`, `mail to`).
    pub detail: String,
    pub at: Option<Timestamp>,
}

/// One raw trace fed into the resolver.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Service label as the trace gave it (name, host, URL, id); `None` when unknown.
    pub service: Option<String>,
    pub identifier: String,
    pub kind: IdentifierKind,
    pub source: AccountSource,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    /// 0..=1 confidence of this one trace.
    pub confidence: f32,
}

/// The merged account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    key: String,
    service: String,
    service_id: Option<String>,
    service_kind: Option<ServiceKind>,
    identifier: String,
    kind: IdentifierKind,
    sources: Vec<AccountSource>,
    disks: Vec<EvidenceId>,
    first_seen: Option<Timestamp>,
    last_seen: Option<Timestamp>,
    confidence: f32,
    /// Keys of accounts with the same identifier (or e-mail local part) elsewhere.
    linked: Vec<String>,
}

impl Account {
    /// Stable key: `<service id or label>|<identifier, case-folded>`.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Service display name.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Catalogue id when the service is catalogued.
    pub fn service_id(&self) -> Option<&str> {
        self.service_id.as_deref()
    }

    pub fn service_kind(&self) -> Option<ServiceKind> {
        self.service_kind
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn kind(&self) -> IdentifierKind {
        self.kind
    }

    pub fn sources(&self) -> &[AccountSource] {
        &self.sources
    }

    pub fn disks(&self) -> &[EvidenceId] {
        &self.disks
    }

    pub fn first_seen(&self) -> Option<Timestamp> {
        self.first_seen
    }

    pub fn last_seen(&self) -> Option<Timestamp> {
        self.last_seen
    }

    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    pub fn linked(&self) -> &[String] {
        &self.linked
    }

    /// The account may hold funds (exchange, web wallet, faucet balance, pool, casino...).
    pub fn holds_funds(&self) -> bool {
        self.service_kind.is_some_and(ServiceKind::holds_funds)
    }

    /// The `(first, last)` seen window when both ends are known.
    pub fn window(&self) -> Option<(Timestamp, Timestamp)> {
        Some((self.first_seen.or(self.last_seen)?, self.last_seen.or(self.first_seen)?))
    }
}
