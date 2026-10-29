//! Pipeline steps. Each one works through a [`StepContext`]: it resumes from its cursor,
//! checks `should_stop` between units and commits results together with the next cursor.

pub(crate) mod archives;
mod artifacts;
mod balances;
mod carve;
mod classify;
mod index;
mod mail;
mod partitions;
pub(crate) mod recheck;
pub(crate) mod recover;
mod scan;
pub(crate) mod search;
mod sweep;
mod wallet_files;

pub use archives::ArchiveSummary;

use crate::Workbench;
use crate::jobs::JobKind;
use crate::jobs::context::StepContext;
use strata_kernel::Result;

pub(crate) use archives::PASSWORDS_KEY;

/// Run one step; returns its summary in words.
pub(crate) fn run(ctx: &StepContext<'_>, kind: JobKind, wb: &Workbench) -> Result<String> {
    match kind {
        JobKind::IndexFiles => index::run(ctx),
        JobKind::Scan => scan::run(ctx, wb),
        JobKind::RecoverPartitions => partitions::run(ctx),
        JobKind::Artifacts => artifacts::run(ctx),
        JobKind::Mail => mail::run(ctx, wb),
        JobKind::ClassifyFiles => classify::run(ctx),
        JobKind::Carve => carve::run(ctx, wb),
        JobKind::Archives => archives::run(ctx),
        JobKind::CheckBalances => balances::run(ctx, &wb.chain_endpoint()),
        JobKind::Search => search::run(ctx),
        JobKind::Recover => recover::run(ctx),
        JobKind::Recheck => recheck::run(ctx),
        JobKind::Tidy => recheck::tidy(ctx),
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
