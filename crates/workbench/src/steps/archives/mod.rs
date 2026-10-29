//! Unpack archives found on the evidence — live, deleted, renamed and carved ones — and
//! analyse every member like any other data. Finished archives commit in batches with the
//! set of archive names done, so a resumed run skips them and redoes at most the one it was in.

mod members;
mod targets;

use crate::catalog::DetectorCatalog;
use crate::jobs::context::{Cursor, StepContext};
use members::MemberAnalyzer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ops::ControlFlow;
use strata_archive::{OpenOptions, SevenZipTool, UnpackLimits, Unpacker};
use strata_case::{ArchiveMemberRow, Attribution};
use strata_kernel::Result;
use strata_kernel::scan::Hit;
use targets::{MAX_ARCHIVE_BYTES, TargetFinder};

/// Case setting: passwords of the user's own archives, one per line.
pub(crate) const PASSWORDS_KEY: &str = "archive_passwords";

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ArchiveSummary {
    pub archives: usize,
    pub nested: usize,
    pub members: usize,
    pub encrypted: usize,
    pub findings: usize,
    pub skipped: usize,
}

impl ArchiveSummary {
    pub fn describe(&self) -> String {
        format!(
            "{} archives ({} nested), {} members, {} encrypted, {} new findings{}",
            self.archives,
            self.nested,
            self.members,
            self.encrypted,
            self.findings,
            if self.skipped > 0 { format!(", {} unreadable or too large", self.skipped) } else { String::new() }
        )
    }
}

/// Archives finished, by name, and the running totals.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ArchivesCursor {
    done: BTreeSet<String>,
    summary: ArchiveSummary,
}

impl Cursor for ArchivesCursor {
    fn note(&self) -> String {
        format!("archive {} ({} unpacked so far)", self.done.len() + 1, self.summary.archives)
    }
}

/// Findings and member rows of the archives unpacked since the last commit.
#[derive(Default)]
struct Batch {
    hits: Vec<(Hit, Attribution)>,
    rows: Vec<ArchiveMemberRow>,
}

impl Batch {
    fn commit(&mut self, ctx: &StepContext<'_>, cur: &mut ArchivesCursor) -> Result<()> {
        let id = ctx.evidence();
        let (hits, rows) = (std::mem::take(&mut self.hits), std::mem::take(&mut self.rows));
        cur.summary.findings += ctx.commit(cur, |w| {
            w.archive_members(id, &rows)?;
            w.hits(id, &hits)
        })?;
        Ok(())
    }
}

fn options(ctx: &StepContext<'_>) -> OpenOptions {
    let case = ctx.case();
    let passwords = case
        .setting(PASSWORDS_KEY)
        .ok()
        .flatten()
        .map(|s| s.lines().map(str::to_string).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    OpenOptions { passwords, scratch: Some(case.root().join("cache").join("archive-tmp")), external: SevenZipTool::detect() }
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let finder = TargetFinder::new(ctx.case(), ctx.source()?);
    let targets = finder.find(id)?;
    let mut cur = match ctx.cursor::<ArchivesCursor>() {
        Some(cur) => cur,
        None => {
            let fresh = ArchivesCursor::default();
            ctx.commit(&fresh, |w| w.clear_archive_members(id))?;
            fresh
        }
    };
    let control = ctx.control();
    control.begin_at(targets.iter().filter(|t| cur.done.contains(&t.name)).count() as u64, targets.len() as u64);
    let unpacker = Unpacker::new(UnpackLimits::default(), options(ctx));
    let analyzer = MemberAnalyzer::new(DetectorCatalog::all());
    let mut batch = Batch::default();
    let pending: Vec<_> = targets.iter().filter(|t| !cur.done.contains(&t.name)).collect();
    for t in pending {
        if ctx.should_stop() {
            break;
        }
        ctx.current(&t.name);
        let report = if t.size > MAX_ARCHIVE_BYTES { None } else { finder.read(id, t).ok() }.map(|bytes| {
            let mut found = Batch::default();
            let report = unpacker.unpack(&t.name, &bytes, t.hint, &mut |m| {
                if ctx.should_stop() {
                    return ControlFlow::Break(());
                }
                ctx.current(m.path);
                let (h, row) = analyzer.analyze(t, m);
                found.hits.extend(h);
                found.rows.push(row);
                ControlFlow::Continue(())
            });
            (report, found)
        });
        // Stopped inside this archive: it is redone on resume, nothing of it is kept.
        if control.is_cancelled() {
            break;
        }
        match report {
            Some((report, found)) if report.archives > 0 => {
                let s = &mut cur.summary;
                s.archives += 1;
                s.nested += report.archives - 1;
                s.members += report.members;
                s.encrypted += report.encrypted;
                ctx.log(format!("unpacked {} from {}", super::count(report.members, "member", "members"), t.name));
                batch.hits.extend(found.hits);
                batch.rows.extend(found.rows);
            }
            _ => cur.summary.skipped += 1,
        }
        cur.done.insert(t.name.clone());
        control.item_done();
        if ctx.tick(1) {
            batch.commit(ctx, &mut cur)?;
        }
    }
    batch.commit(ctx, &mut cur)?;
    Ok(cur.summary.describe())
}
