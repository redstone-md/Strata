use strata_accounts::Account;
use strata_chain::AddressHistory;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_timeline::TimelineEvent;

/// A key, seed, wallet or address finding with the times of the file it sits in.
#[derive(Debug, Clone)]
pub struct KeyFinding {
    pub hit_id: i64,
    pub evidence: EvidenceId,
    pub category: HitCategory,
    /// Detector label (`WIF private key`, `Bitcoin Core wallet`).
    pub label: String,
    pub value: String,
    pub file_path: Option<String>,
    pub deleted: bool,
    pub file_created: Option<Timestamp>,
    pub file_modified: Option<Timestamp>,
    /// The address itself or addresses derived from the key / listed in the wallet.
    pub addresses: Vec<String>,
}

impl KeyFinding {
    /// File name for sentences (`wallet.dat`), or the label when the hit is not in a file.
    pub fn file_name(&self) -> &str {
        self.file_path.as_deref().and_then(|p| p.rsplit(['/', '\\']).next()).filter(|n| !n.is_empty()).unwrap_or(&self.label)
    }

    /// Key material proper (not just an address).
    pub fn is_secret(&self) -> bool {
        matches!(self.category, HitCategory::PrivateKey | HitCategory::ExtendedKey | HitCategory::Mnemonic | HitCategory::Wallet)
    }

    /// What the finding is, for sentences.
    pub fn noun(&self) -> &'static str {
        match self.category {
            HitCategory::Mnemonic => "seed phrase",
            HitCategory::Wallet => "wallet",
            HitCategory::ExtendedKey => "extended key",
            HitCategory::PrivateKey => "private key",
            HitCategory::Address => "address",
            _ => "finding",
        }
    }
}

/// A stored timeline event with its row id.
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub id: i64,
    pub evidence: EvidenceId,
    pub event: TimelineEvent,
}

/// Everything the engine correlates.
#[derive(Debug, Clone, Default)]
pub struct LeadInputs {
    pub keys: Vec<KeyFinding>,
    pub histories: Vec<AddressHistory>,
    pub events: Vec<EventRecord>,
    pub accounts: Vec<Account>,
}
