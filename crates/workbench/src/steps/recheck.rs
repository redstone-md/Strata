//! Re-check stored findings after detector rules improve. Each finding's surroundings are read
//! again (a few KiB of the disk) and run through its detector: findings it no longer reports
//! are removed, the rest take its current confidence. Repeats are then folded and triage
//! re-applied, so a case scanned by an older version reads as if scanned today.

use crate::catalog::DetectorCatalog;
use crate::jobs::context::{Cursor, StepContext};
use crate::triage::Triage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use strata_case::{RecheckRow, Verdict};
use strata_kernel::Result;
use strata_kernel::scan::{Detector, Hit};
use strata_source::BlockSource;

/// Detectors whose rules changed since findings may have been stored.
pub(crate) const DETECTORS: &[&str] = &["crypto.hex_key", "crypto.minikey", "crypto.mnemonic"];
/// Bytes read on each side of a finding: covers every detector's context window.
const MARGIN: u64 = 4096;
const BATCH: usize = 500;

#[derive(Debug, Default, Serialize, Deserialize)]
struct RecheckCursor {
    /// Every finding with a lower row id is re-checked.
    after: i64,
    checked: usize,
    removed: usize,
    changed: usize,
}

impl Cursor for RecheckCursor {
    fn note(&self) -> String {
        format!("finding #{} ({} re-checked)", self.after, self.checked)
    }
}

fn verdict(source: &dyn BlockSource, detector: &dyn Detector, row: &RecheckRow) -> Result<Verdict> {
    let from = row.offset.saturating_sub(MARGIN);
    let to = (row.offset + row.len as u64 + MARGIN).min(source.len());
    let bytes = source.read_vec(from, (to - from) as usize)?;
    let mut hits: Vec<Hit> = Vec::new();
    detector.scan(&bytes, from, &mut hits);
    Ok(hits.into_iter().find(|h| h.offset == row.offset && h.value == row.value).map(|h| (h.confidence.get(), h.details)))
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let mut cur: RecheckCursor = ctx.cursor().unwrap_or_default();
    let detectors: HashMap<&str, Arc<dyn Detector>> =
        DetectorCatalog::all().into_iter().filter(|d| DETECTORS.contains(&d.id())).map(|d| (d.id(), d)).collect();
    let source = ctx.source()?;
    let left = ctx.case().recheck_count(id, DETECTORS)?;
    ctx.control().begin_at(cur.checked as u64, cur.checked as u64 + left);
    loop {
        let rows = ctx.case().recheck_rows(id, DETECTORS, cur.after, BATCH)?;
        if rows.is_empty() {
            break;
        }
        let mut verdicts: Vec<(i64, Verdict)> = Vec::with_capacity(rows.len());
        for row in &rows {
            if ctx.should_stop() {
                break;
            }
            let Some(detector) = detectors.get(row.detector.as_str()) else { continue };
            verdicts.push((row.id, verdict(source.as_ref(), detector.as_ref(), row)?));
            cur.after = row.id;
            cur.checked += 1;
            ctx.control().item_done();
        }
        let applied = std::mem::take(&mut verdicts);
        let (removed, changed) = ctx.commit(&cur, |w| w.rechecked(&applied))?;
        cur.removed += removed;
        cur.changed += changed;
        if ctx.should_stop() {
            return Ok(String::new());
        }
    }
    let (folded, downgraded) = tidy_findings(ctx)?;
    ctx.commit(&cur, |_| Ok(()))?;
    let summary = format!(
        "{} re-checked, {} no longer findings, {} rescored, {folded} repeated copies folded, {downgraded} inside system files",
        cur.checked, cur.removed, cur.changed
    );
    ctx.log(summary.clone());
    Ok(summary)
}

/// Fold repeated copies into counts and re-apply triage. Both are idempotent, so the step
/// needs no cursor: an interrupted run simply runs again.
fn tidy_findings(ctx: &StepContext<'_>) -> Result<(usize, usize)> {
    let id = ctx.evidence();
    ctx.current("folding repeated copies");
    let folded = ctx.case().compact_repeats(id)?;
    ctx.current("re-applying triage");
    Ok((folded, Triage::new(ctx.case()).run(id)?))
}

/// The `Tidy` step: only the repeat cap and triage, for cases whose findings are otherwise
/// current.
pub(super) fn tidy(ctx: &StepContext<'_>) -> Result<String> {
    ctx.control().begin_at(0, 2);
    let (folded, downgraded) = tidy_findings(ctx)?;
    ctx.control().item_done();
    ctx.control().item_done();
    let summary = format!("{folded} repeated copies folded, {downgraded} inside system files");
    ctx.log(summary.clone());
    Ok(summary)
}
