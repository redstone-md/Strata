//! Leads context — the date analyser: what may fit where.
//!
//! [`LeadEngine`] correlates, per disk and across disks, the on-chain activity windows of found
//! and derived addresses, crypto-tagged timeline events (faucet, exchange and pool visits,
//! wallet runs and downloads, searches, money mails), account first/last-seen dates and the
//! times of wallet and key files. It produces ranked [`Lead`]s with plain-sentence
//! explanations built only from facts in its inputs. Scoring rules are data in [`scoring`].

mod engine;
mod fmt;
mod inputs;
mod lead;
mod rules;
pub mod scoring;
mod signal;

pub use engine::LeadEngine;
pub use inputs::{EventRecord, KeyFinding, LeadInputs};
pub use lead::{Lead, LeadRef, LeadRule};
pub use signal::{Signal, SignalClass};

#[cfg(test)]
mod tests;
