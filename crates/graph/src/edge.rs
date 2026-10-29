//! Edges: why two entities are connected, how often the case says so, and the concrete
//! evidence (findings, files, messages, account traces, transactions, leads).

use serde::{Deserialize, Serialize};
use strata_accounts::{AccountSource, SourceRef};
use strata_kernel::{EvidenceId, Timestamp};

/// Evidence kept per edge; the count goes on.
pub(crate) const MAX_EVIDENCE: usize = 12;

/// The reason two nodes are linked. Direction reads `from → to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Identity → account: the identifier is used on a service.
    HasAccount,
    /// Account → service.
    OnService,
    /// Identity → service: mail from the service reached this mailbox.
    MailFromService,
    /// Secret → address it derives or a wallet holds.
    Derives,
    /// Address ↔ address: both appear in one transaction.
    SameTransaction,
    /// Finding ↔ finding: found in the same file (a login next to a key).
    CoOccurs,
    /// Finding → the file it is in.
    FoundIn,
    /// File or finding → the disk it is on.
    OnDisk,
    /// Identity ↔ identity: mail between them.
    Corresponded,
    /// Identity → message it sent.
    Sent,
    /// Message → identity it was sent to.
    Received,
    /// Message → address, key or identity named in its body.
    Mentions,
    /// Lead → what it rests on.
    Refers,
}

impl EdgeKind {
    /// Short verb phrase, read `from <label> to`.
    pub fn label(self) -> &'static str {
        match self {
            Self::HasAccount => "has an account",
            Self::OnService => "on service",
            Self::MailFromService => "got mail from",
            Self::Derives => "derives",
            Self::SameTransaction => "same transaction",
            Self::CoOccurs => "in the same file as",
            Self::FoundIn => "found in",
            Self::OnDisk => "on disk",
            Self::Corresponded => "corresponded with",
            Self::Sent => "sent",
            Self::Received => "sent to",
            Self::Mentions => "mentions",
            Self::Refers => "points at",
        }
    }

    /// The same link read from its `to` end.
    pub fn reverse_label(self) -> &'static str {
        match self {
            Self::HasAccount => "account of",
            Self::OnService => "has the account",
            Self::MailFromService => "sent mail to",
            Self::Derives => "derived from",
            Self::FoundIn | Self::OnDisk => "holds",
            Self::Sent => "sent by",
            Self::Received => "received",
            Self::Mentions => "mentioned in",
            Self::Refers => "in the lead",
            Self::SameTransaction | Self::CoOccurs | Self::Corresponded => self.label(),
        }
    }

    /// How much the link says about belonging together, 0..=1. Drives ranking, the order of
    /// neighbours in a view and the pull of the layout.
    pub fn strength(self) -> f32 {
        match self {
            Self::Derives | Self::CoOccurs => 1.0,
            Self::HasAccount | Self::SameTransaction => 0.9,
            Self::Mentions | Self::MailFromService => 0.8,
            Self::Refers | Self::Sent | Self::Received => 0.7,
            Self::Corresponded => 0.6,
            Self::FoundIn | Self::OnService => 0.5,
            Self::OnDisk => 0.2,
        }
    }

    /// Both ends play the same role (the edge has no reading direction).
    pub fn symmetric(self) -> bool {
        matches!(self, Self::SameTransaction | Self::CoOccurs | Self::Corresponded)
    }
}

/// One concrete reason behind an edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// A stored finding (hit row), where it was found.
    Finding { hit: i64, disk: EvidenceId, file: Option<String> },
    /// A trace naming an account (saved login, URL field, mail...).
    Trace { disk: EvidenceId, detail: String, at: Option<Timestamp>, hit: Option<i64>, event: Option<i64>, file: Option<String> },
    /// A recovered e-mail message.
    Message { id: i64, at: Option<Timestamp>, subject: String },
    /// An on-chain transaction.
    Transaction { txid: String, at: Option<Timestamp> },
    Lead { id: String, title: String },
}

impl Evidence {
    pub(crate) fn trace(s: &AccountSource) -> Self {
        let (hit, event, file) = match &s.origin {
            SourceRef::Hit(id) => (Some(*id), None, None),
            SourceRef::Event(id) => (None, Some(*id), None),
            SourceRef::File(path) => (None, None, Some(path.clone())),
        };
        Self::Trace { disk: s.evidence, detail: s.detail.clone(), at: s.at, hit, event, file }
    }

    pub fn at(&self) -> Option<Timestamp> {
        match self {
            Self::Trace { at, .. } | Self::Message { at, .. } | Self::Transaction { at, .. } => *at,
            _ => None,
        }
    }

    /// One line for a detail panel.
    pub fn describe(&self) -> String {
        let when = |at: &Option<Timestamp>| at.map(|t| format!(" ({t})")).unwrap_or_default();
        match self {
            Self::Finding { hit, file: Some(f), .. } => format!("finding #{hit} in {f}"),
            Self::Finding { hit, file: None, .. } => format!("finding #{hit} outside any file"),
            Self::Trace { detail, at, .. } => format!("{detail}{}", when(at)),
            Self::Message { subject, at, .. } if subject.is_empty() => format!("message without subject{}", when(at)),
            Self::Message { subject, at, .. } => format!("message \"{subject}\"{}", when(at)),
            Self::Transaction { txid, at } => format!("transaction {txid}{}", when(at)),
            Self::Lead { title, .. } => format!("lead \"{title}\""),
        }
    }
}

/// A typed, evidenced link between two nodes (indices into the graph's node list).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) kind: EdgeKind,
    pub(crate) count: u64,
    pub(crate) evidence: Vec<Evidence>,
}

impl Edge {
    pub(crate) fn new(from: usize, to: usize, kind: EdgeKind) -> Self {
        Self { from, to, kind, count: 0, evidence: Vec::new() }
    }

    /// Count one more piece of evidence, keeping the first [`MAX_EVIDENCE`] distinct ones.
    pub(crate) fn add(&mut self, evidence: Option<Evidence>) {
        self.count += 1;
        if let Some(e) = evidence
            && self.evidence.len() < MAX_EVIDENCE
            && !self.evidence.contains(&e)
        {
            self.evidence.push(e);
        }
    }

    pub fn from(&self) -> usize {
        self.from
    }

    pub fn to(&self) -> usize {
        self.to
    }

    pub fn kind(&self) -> EdgeKind {
        self.kind
    }

    /// How many times the case shows this link (messages, traces, shared files...).
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// The other end, seen from `node`.
    pub fn other(&self, node: usize) -> usize {
        if self.from == node { self.to } else { self.from }
    }

    /// Weight of the link: its kind's strength, a little more for repeated evidence.
    pub fn weight(&self) -> f32 {
        self.kind.strength() * (1.0 + (self.count.max(1) as f32).ln() * 0.15)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_first_distinct_evidence_and_counts_all() {
        let mut e = Edge::new(0, 1, EdgeKind::Corresponded);
        for i in 0..20 {
            e.add(Some(Evidence::Message { id: i % 15, at: None, subject: String::new() }));
        }
        e.add(None);
        assert_eq!((e.count(), e.evidence().len()), (21, MAX_EVIDENCE));
        assert_eq!(e.other(1), 0);
        assert!(e.weight() > EdgeKind::Corresponded.strength());
    }
}
