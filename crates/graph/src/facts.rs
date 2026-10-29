//! What the graph is built from: aggregated, capped rows the case store hands over. Nothing
//! here holds every finding of a case; [`Limits`] bounds each kind of row.

use std::collections::BTreeSet;
use strata_accounts::Account;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::Lead;

/// How much the store reads for one graph. Real cases hold millions of identity findings, most
/// of them noise; these caps keep the build to seconds and the graph to tens of thousands of
/// nodes.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Findings below this confidence are left out (the workbench's noise floor).
    pub min_confidence: f32,
    /// Key, seed and wallet placements, most confident first.
    pub secrets: usize,
    /// Files holding secrets whose other findings are read (co-occurrence).
    pub secret_files: usize,
    /// Identity and address placements in those files, plus identities from artefacts.
    pub placements: usize,
    /// Identity values whose spread over the case is measured.
    pub spreads: usize,
    /// Sample of places kept per measured value.
    pub spread_paths: usize,
    pub accounts: usize,
    pub messages: usize,
    /// Messages whose body is searched for addresses and identities, and bytes read of each.
    pub bodies: usize,
    pub body_bytes: usize,
    pub leads: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            min_confidence: 0.2,
            secrets: 20_000,
            secret_files: 2_000,
            placements: 40_000,
            spreads: 8_000,
            spread_paths: 16,
            accounts: 8_000,
            messages: 200_000,
            bodies: 50_000,
            body_bytes: 8 * 1024,
            leads: 2_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiskFact {
    pub id: EvidenceId,
    pub label: String,
}

/// One stored finding where it was found.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingFact {
    pub hit: i64,
    pub disk: EvidenceId,
    pub category: HitCategory,
    pub detector: String,
    pub label: String,
    pub value: String,
    pub confidence: f32,
    pub file: Option<String>,
    /// The file is deleted (or the finding sits in free space of a deleted partition).
    pub deleted: bool,
    /// Created / modified time of the file.
    pub file_times: (Option<Timestamp>, Option<Timestamp>),
    /// Addresses the finding derives or lists (keys, seeds, wallets).
    pub addresses: Vec<String>,
    /// Detail an artefact gave (`saved browser login`), for identities read from artefacts.
    pub detail: Option<String>,
}

impl FindingFact {
    pub fn is_secret(&self) -> bool {
        matches!(self.category, HitCategory::PrivateKey | HitCategory::ExtendedKey | HitCategory::Mnemonic | HitCategory::Wallet)
    }

    /// Read from an artefact (browser logins, mail settings, miner configs), not from raw bytes.
    pub fn from_artefact(&self) -> bool {
        self.detector.starts_with("artifacts.")
    }
}

/// How widely an identity value is spread over the case: package lists and dumps repeat
/// strangers' addresses in thousands of places.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpreadFact {
    /// Case-folded value.
    pub value: String,
    pub copies: u64,
    pub files: u64,
    pub disks: Vec<EvidenceId>,
    /// Some of the files it is in (not every one).
    pub sample_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TxFact {
    pub txid: String,
    pub at: Option<Timestamp>,
}

/// An address looked up on chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainFact {
    pub address: String,
    pub funded_sat: u64,
    pub spent_sat: u64,
    pub tx_count: u64,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    /// Transactions from the cached history, when fetched.
    pub txs: Vec<TxFact>,
}

/// One message's envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct MailFact {
    pub id: i64,
    pub disk: EvidenceId,
    pub at: Option<Timestamp>,
    /// Found in a live mailbox file (not deleted, not carved).
    pub live: bool,
    /// Lowercased addresses.
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub subject: String,
}

/// A message body naming an address, key or identity of the graph.
#[derive(Debug, Clone, PartialEq)]
pub struct MentionFact {
    pub message: i64,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub disks: Vec<DiskFact>,
    pub findings: Vec<FindingFact>,
    pub spreads: Vec<SpreadFact>,
    pub accounts: Vec<Account>,
    pub chain: Vec<ChainFact>,
    pub mail: Vec<MailFact>,
    pub mentions: Vec<MentionFact>,
    pub leads: Vec<Lead>,
}

impl Facts {
    /// Identity values whose spread the store should measure: identities among the findings,
    /// account identifiers and mail parties of live mailboxes, at most `limit`, findings first.
    pub fn identity_values(&self, limit: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        let findings = self.findings.iter().filter(|f| f.category == HitCategory::Identity).map(|f| f.value.as_str());
        let accounts = self.accounts.iter().map(|a| a.identifier());
        let mail = self.mail.iter().filter(|m| m.live).flat_map(|m| m.from.iter().chain(&m.to)).map(String::as_str);
        for v in findings.chain(accounts).chain(mail) {
            if out.len() >= limit {
                break;
            }
            let folded = v.trim().to_lowercase();
            if !folded.is_empty() && seen.insert(folded.clone()) {
                out.push(folded);
            }
        }
        out
    }

    /// Values a mail body may name that would add a link: addresses and keys among the
    /// findings and on chain, and identities among the findings and accounts. Case-folded
    /// for identities.
    pub fn mention_targets(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for f in &self.findings {
            match f.category {
                HitCategory::Identity if f.value.len() >= 4 => {
                    out.insert(f.value.to_lowercase());
                }
                HitCategory::Address | HitCategory::PrivateKey | HitCategory::ExtendedKey => {
                    out.insert(f.value.clone());
                }
                _ => {}
            }
            out.extend(f.addresses.iter().cloned());
        }
        out.extend(self.chain.iter().map(|c| c.address.clone()));
        out.extend(self.accounts.iter().map(|a| a.identifier().to_lowercase()).filter(|v| v.len() >= 4));
        out
    }
}
