//! Pipeline steps. Each one works through a [`StepContext`]: it resumes from its cursor,
//! checks `should_stop` between units and commits results together with the next cursor.

mod archives;
mod artifacts;
mod balances;
mod carve;
mod classify;
mod index;
mod scan;
mod wallet_files;

pub use archives::ArchiveSummary;

use crate::jobs::JobKind;
use crate::jobs::context::StepContext;
use strata_kernel::Result;

pub(crate) use archives::PASSWORDS_KEY;

/// Run one step; returns its summary in words.
pub(crate) fn run(ctx: &StepContext<'_>, kind: JobKind, chain_endpoint: &str) -> Result<String> {
    match kind {
        JobKind::IndexFiles => index::run(ctx),
        JobKind::Scan => scan::run(ctx),
        JobKind::Artifacts => artifacts::run(ctx),
        JobKind::ClassifyFiles => classify::run(ctx),
        JobKind::Carve => carve::run(ctx),
        JobKind::Archives => archives::run(ctx),
        JobKind::CheckBalances => balances::run(ctx, chain_endpoint),
    }
}

/// `1 file`, `3 files` for log lines.
pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `1, 2 and 3` for cursor notes.
pub(crate) fn list<T: std::fmt::Display>(items: &[T]) -> String {
    match items {
        [] => "none".into(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.iter().map(T::to_string).collect::<Vec<_>>().join(", ")),
    }
}
