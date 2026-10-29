//! Nodes of the connection graph: what an entity is, its stable key, and what ranking learned
//! about it.

use serde::{Deserialize, Serialize};
use std::fmt;
use strata_kernel::{EvidenceId, Timestamp};

/// What a node stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// An e-mail address, login, nickname or user id: a person-like identity.
    Identity,
    /// One identifier on one service.
    Account,
    /// A service of the catalogue (exchange, faucet, pool, web wallet...).
    Service,
    /// A private key, extended key, seed phrase or wallet file.
    Secret,
    /// A cryptocurrency address.
    Address,
    /// A file holding findings.
    File,
    Disk,
    /// A recovered e-mail message that mentions something of interest.
    Message,
    Lead,
}

impl NodeKind {
    pub const ALL: [NodeKind; 9] =
        [Self::Identity, Self::Account, Self::Service, Self::Secret, Self::Address, Self::File, Self::Disk, Self::Message, Self::Lead];

    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Account => "account",
            Self::Service => "service",
            Self::Secret => "key or wallet",
            Self::Address => "address",
            Self::File => "file",
            Self::Disk => "disk",
            Self::Message => "message",
            Self::Lead => "lead",
        }
    }

    /// Plural display name (filters, legends).
    pub fn plural(self) -> &'static str {
        match self {
            Self::Identity => "Identities",
            Self::Account => "Accounts",
            Self::Service => "Services",
            Self::Secret => "Keys & wallets",
            Self::Address => "Addresses",
            Self::File => "Files",
            Self::Disk => "Disks",
            Self::Message => "Mail",
            Self::Lead => "Leads",
        }
    }

    /// Hubs join many unrelated things (everything on a disk, every user of a service): views
    /// show them but never walk through them.
    pub fn is_hub(self) -> bool {
        matches!(self, Self::Disk | Self::Service)
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name || k.label() == name)
    }

    /// Stable lower-case name (`identity`, `secret`...).
    pub fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Account => "account",
            Self::Service => "service",
            Self::Secret => "secret",
            Self::Address => "address",
            Self::File => "file",
            Self::Disk => "disk",
            Self::Message => "message",
            Self::Lead => "lead",
        }
    }
}

/// Stable identity of a node across rebuilds: a kind prefix plus the value (case-folded where
/// case does not matter: e-mails, logins, service names).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeKey(String);

impl NodeKey {
    const PREFIXES: [&'static str; 10] = ["id:", "acct:", "svc:", "key:", "wallet:", "addr:", "file:", "disk:", "mail:", "lead:"];

    pub fn identity(value: &str) -> Self {
        Self(format!("id:{}", value.trim().to_lowercase()))
    }

    /// From an account key (`service|identifier`).
    pub fn account(key: &str) -> Self {
        Self(format!("acct:{key}"))
    }

    pub fn service(key: &str) -> Self {
        Self(format!("svc:{}", key.trim().to_lowercase()))
    }

    /// A key or seed, by value (keys are case-sensitive).
    pub fn secret(value: &str) -> Self {
        Self(format!("key:{value}"))
    }

    /// A wallet file: the file itself is the finding.
    pub fn wallet(disk: EvidenceId, place: &str) -> Self {
        Self(format!("wallet:{}:{place}", disk.get()))
    }

    pub fn address(address: &str) -> Self {
        Self(format!("addr:{address}"))
    }

    pub fn file(disk: EvidenceId, path: &str) -> Self {
        Self(format!("file:{}:{path}", disk.get()))
    }

    pub fn disk(disk: EvidenceId) -> Self {
        Self(format!("disk:{}", disk.get()))
    }

    pub fn message(id: i64) -> Self {
        Self(format!("mail:{id}"))
    }

    pub fn lead(id: &str) -> Self {
        Self(format!("lead:{id}"))
    }

    /// A key as written by [`Self::as_str`]; `None` for free text.
    pub fn parse(text: &str) -> Option<Self> {
        Self::PREFIXES.iter().any(|p| text.starts_with(p) && text.len() > p.len()).then(|| Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// On-chain state of an address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    pub funded_sat: u64,
    pub spent_sat: u64,
    pub tx_count: u64,
}

impl ChainState {
    pub fn balance_sat(self) -> u64 {
        self.funded_sat.saturating_sub(self.spent_sat)
    }

    pub fn used(self) -> bool {
        self.tx_count > 0 || self.funded_sat > 0
    }
}

/// Facts that change how a node is drawn and ranked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flags {
    /// Holds coins now.
    pub funded: bool,
    /// Has an on-chain history.
    pub used: bool,
    /// The most likely owner of the machine.
    pub owner: bool,
    /// Only found in deleted files or free space.
    pub deleted: bool,
    /// Found on more than one disk.
    pub cross_disk: bool,
}

/// One entity of the case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub(crate) key: NodeKey,
    pub(crate) kind: NodeKind,
    pub(crate) label: String,
    pub(crate) caption: String,
    pub(crate) score: f32,
    pub(crate) flags: Flags,
    pub(crate) disks: Vec<EvidenceId>,
    pub(crate) first_seen: Option<Timestamp>,
    pub(crate) last_seen: Option<Timestamp>,
    pub(crate) hit: Option<i64>,
    pub(crate) chain: Option<ChainState>,
    pub(crate) why: Vec<String>,
}

impl Node {
    pub(crate) fn new(key: NodeKey, kind: NodeKind, label: impl Into<String>, caption: impl Into<String>) -> Self {
        Self {
            key,
            kind,
            label: label.into(),
            caption: caption.into(),
            score: 0.0,
            flags: Flags::default(),
            disks: Vec::new(),
            first_seen: None,
            last_seen: None,
            hit: None,
            chain: None,
            why: Vec::new(),
        }
    }

    pub fn key(&self) -> &NodeKey {
        &self.key
    }

    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// The value as shown: an address, an e-mail, a file name, a lead title.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// What it is in a few words (`WIF private key`, `exchange account on Mt. Gox`).
    pub fn caption(&self) -> &str {
        &self.caption
    }

    /// 0..=100: closeness to money and ownership.
    pub fn score(&self) -> f32 {
        self.score
    }

    pub fn flags(&self) -> Flags {
        self.flags
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

    /// The stored finding to open, when the node came from one.
    pub fn hit(&self) -> Option<i64> {
        self.hit
    }

    pub fn chain(&self) -> Option<ChainState> {
        self.chain
    }

    /// Why the node ranks where it does, one short sentence each.
    pub fn why(&self) -> &[String] {
        &self.why
    }

    pub(crate) fn seen(&mut self, at: Option<Timestamp>) {
        let Some(at) = at else { return };
        self.first_seen = Some(self.first_seen.map_or(at, |f| f.min(at)));
        self.last_seen = Some(self.last_seen.map_or(at, |l| l.max(at)));
    }

    pub(crate) fn on_disk(&mut self, disk: EvidenceId) {
        if !self.disks.contains(&disk) {
            self.disks.push(disk);
            self.disks.sort();
            self.flags.cross_disk = self.disks.len() > 1;
        }
    }

    pub(crate) fn because(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.why.contains(&reason) {
            self.why.push(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_fold_case_where_it_does_not_matter() {
        assert_eq!(NodeKey::identity(" Olga.Test@Example.RU "), NodeKey::identity("olga.test@example.ru"));
        assert_ne!(NodeKey::secret("5Kabc"), NodeKey::secret("5KABC"));
        assert_eq!(NodeKey::parse("addr:1Abc").map(|k| k.to_string()), Some("addr:1Abc".to_string()));
        assert_eq!(NodeKey::parse("olga@example.ru"), None);
        assert_eq!(NodeKey::parse("id:"), None);
        assert_eq!(NodeKind::parse("secret"), Some(NodeKind::Secret));
    }

    #[test]
    fn tracks_dates_and_disks() {
        let mut n = Node::new(NodeKey::address("1A"), NodeKind::Address, "1A", "address");
        n.seen(Timestamp::from_unix_secs(1_300_000_200));
        n.seen(Timestamp::from_unix_secs(1_300_000_100));
        n.seen(None);
        assert_eq!((n.first_seen().map(|t| t.unix_secs()), n.last_seen().map(|t| t.unix_secs())), (Some(1_300_000_100), Some(1_300_000_200)));
        n.on_disk(EvidenceId::new(2));
        n.on_disk(EvidenceId::new(1));
        n.on_disk(EvidenceId::new(2));
        assert_eq!(n.disks(), [EvidenceId::new(1), EvidenceId::new(2)]);
        assert!(n.flags().cross_disk);
    }
}
