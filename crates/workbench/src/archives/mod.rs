//! Unpack archives found on the evidence — live, deleted, renamed and carved ones — and
//! analyse every member like any other data.

mod members;
mod targets;

use crate::catalog::DetectorCatalog;
use members::MemberAnalyzer;
use std::ops::ControlFlow;
use strata_archive::{OpenOptions, SevenZipTool, UnpackLimits, Unpacker};
use strata_case::{ArchiveMemberRow, Case};
use strata_engine::ScanControl;
use strata_kernel::{EvidenceId, Result};
use targets::{MAX_ARCHIVE_BYTES, TargetFinder};

/// Case setting: passwords of the user's own archives, one per line.
pub(crate) const PASSWORDS_KEY: &str = "archive_passwords";

#[derive(Debug, Default, Clone, Copy)]
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

pub struct ArchiveUnpacker<'a> {
    case: &'a Case,
}

impl<'a> ArchiveUnpacker<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    fn options(&self) -> OpenOptions {
        let passwords = self
            .case
            .setting(PASSWORDS_KEY)
            .ok()
            .flatten()
            .map(|s| s.lines().map(str::to_string).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        OpenOptions { passwords, scratch: Some(self.case.root().join("cache").join("archive-tmp")), external: SevenZipTool::detect() }
    }

    pub fn run(&self, id: EvidenceId, control: &ScanControl) -> Result<ArchiveSummary> {
        let finder = TargetFinder::new(self.case);
        let targets = finder.find(id)?;
        control.begin_items(targets.len() as u64);
        let unpacker = Unpacker::new(UnpackLimits::default(), self.options());
        let analyzer = MemberAnalyzer::new(DetectorCatalog::all());
        let mut summary = ArchiveSummary::default();
        let mut rows: Vec<ArchiveMemberRow> = Vec::new();
        for t in &targets {
            if control.is_cancelled() {
                break;
            }
            control.item_done();
            if t.size > MAX_ARCHIVE_BYTES {
                summary.skipped += 1;
                continue;
            }
            let Ok(bytes) = finder.read(id, t) else {
                summary.skipped += 1;
                continue;
            };
            let mut hits = Vec::new();
            let report = unpacker.unpack(&t.name, &bytes, t.hint, &mut |m| {
                if control.is_cancelled() {
                    return ControlFlow::Break(());
                }
                let (h, row) = analyzer.analyze(t, m);
                hits.extend(h);
                rows.push(row);
                ControlFlow::Continue(())
            });
            if report.archives == 0 {
                summary.skipped += 1;
                continue;
            }
            summary.archives += 1;
            summary.nested += report.archives - 1;
            summary.members += report.members;
            summary.encrypted += report.encrypted;
            summary.findings += self.case.store_hits(id, &hits)?;
        }
        if !control.is_cancelled() {
            self.case.store_archive_members(id, &rows)?;
        }
        Ok(summary)
    }
}
