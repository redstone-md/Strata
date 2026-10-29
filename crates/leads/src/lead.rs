use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Timestamp};

/// Which rule produced a lead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeadRule {
    /// A found key's address moved coins at a time the timeline shows crypto activity.
    OnChainActivity,
    /// A wallet or key file was written while the user was active on a service.
    WalletFileInWindow,
    /// A seed or key turned up in a file created right after wallet software arrived.
    SecretAfterInstall,
    /// An account on a fund-holding service worth checking for balances and withdrawals.
    AccountCheck,
    /// A burst of crypto activity with no wallet or key from that time found.
    ActivityWithoutWallet,
}

impl LeadRule {
    pub fn label(self) -> &'static str {
        match self {
            Self::OnChainActivity => "On-chain activity",
            Self::WalletFileInWindow => "Wallet file in an active period",
            Self::SecretAfterInstall => "Secret after wallet install",
            Self::AccountCheck => "Account to check",
            Self::ActivityWithoutWallet => "Activity without a wallet",
        }
    }
}

/// What a lead points at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LeadRef {
    /// Stored finding id.
    Hit(i64),
    /// Stored timeline event id.
    Event(i64),
    Address(String),
    /// Account key (`service|identifier`).
    Account(String),
}

/// A ranked hypothesis built only from facts in the case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lead {
    /// Stable id: the rule plus what it is about, so a rebuild keeps the same ids.
    pub id: String,
    pub rule: LeadRule,
    pub title: String,
    /// Plain sentences, each one a fact or the conclusion drawn from them.
    pub explanation: Vec<String>,
    /// 0..=100.
    pub score: f32,
    pub refs: Vec<LeadRef>,
    /// The period the lead is about.
    pub window: Option<(Timestamp, Timestamp)>,
    pub evidence: Vec<EvidenceId>,
}

impl Lead {
    pub fn hits(&self) -> impl Iterator<Item = i64> + '_ {
        self.refs.iter().filter_map(|r| if let LeadRef::Hit(id) = r { Some(*id) } else { None })
    }

    pub fn events(&self) -> impl Iterator<Item = i64> + '_ {
        self.refs.iter().filter_map(|r| if let LeadRef::Event(id) = r { Some(*id) } else { None })
    }

    pub fn addresses(&self) -> impl Iterator<Item = &str> + '_ {
        self.refs.iter().filter_map(|r| if let LeadRef::Address(a) = r { Some(a.as_str()) } else { None })
    }

    pub fn accounts(&self) -> impl Iterator<Item = &str> + '_ {
        self.refs.iter().filter_map(|r| if let LeadRef::Account(a) = r { Some(a.as_str()) } else { None })
    }

    /// The explanation as one paragraph.
    pub fn text(&self) -> String {
        self.explanation.join(" ")
    }
}
