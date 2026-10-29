//! One module per lead rule. Every rule reads the shared [`crate::engine::Context`] and only
//! states facts found in it; scores come from [`crate::scoring`].

pub(crate) mod account_check;
pub(crate) mod after_install;
pub(crate) mod gaps;
pub(crate) mod onchain;
pub(crate) mod wallet_window;

use crate::engine::Support;
use crate::fmt::{day, relative, sentence};
use crate::inputs::KeyFinding;
use strata_kernel::{EvidenceId, Timestamp};

/// `Private key found in C:\…\wallet.dat (deleted file).`
pub(crate) fn found_in(key: &KeyFinding) -> String {
    let place = key.file_path.as_deref().map_or_else(|| " on the disk".to_string(), |p| format!(" in {p}"));
    let deleted = if key.deleted { " (deleted file)" } else { "" };
    sentence(format!("{} found{place}{deleted}.", key.noun()))
}

/// One sentence per supporting signal: `The same day the user visited the faucet X.`
pub(crate) fn support_sentences(support: &Support<'_>, anchor: Timestamp) -> Vec<String> {
    support
        .signals
        .iter()
        .map(|(s, _)| {
            let when = relative(s.at, anchor);
            let date = if when == "the same day" { String::new() } else { format!(" ({})", day(s.at)) };
            sentence(format!("{when}{date} the user {}.", s.describe()))
        })
        .collect()
}

/// Distinct evidence ids, sorted.
pub(crate) fn evidence_of(ids: impl IntoIterator<Item = EvidenceId>) -> Vec<EvidenceId> {
    let mut v: Vec<EvidenceId> = ids.into_iter().collect();
    v.sort();
    v.dedup();
    v
}
