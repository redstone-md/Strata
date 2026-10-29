//! Deep scan: every detector over every byte, resumed from the stored watermark. Hits, the
//! watermark and the job checkpoint commit together; the disk index profiler watches the same
//! chunks and is saved alongside (a gap between its last save and the watermark is filled by
//! an observer-only pass before the scan continues).

use crate::Workbench;
use crate::catalog::DetectorCatalog;
use crate::jobs::context::{Cursor, StepContext};
use crate::triage::Triage;
use serde::{Deserialize, Serialize};
use strata_engine::Scanner;
use strata_kernel::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ScanCursor {
    /// Every byte below this offset is scanned and its hits stored.
    watermark: u64,
}

impl Cursor for ScanCursor {
    fn note(&self) -> String {
        format!("offset 0x{:X}", self.watermark)
    }
}

pub(super) fn run(ctx: &StepContext<'_>, wb: &Workbench) -> Result<String> {
    let id = ctx.evidence();
    let index = wb.index();
    let builder = index.prepare(id)?;
    let scanner = Scanner::new(DetectorCatalog::all()).with_workers(wb.scan_threads()).with_observer(builder.clone());
    let len = ctx.case().source(id)?.len().max(1);
    let summary = index.run_scan(id, &builder, ctx.control(), || {
        let mut logged = None;
        ctx.case().scan_with(id, &scanner, ctx.control(), ctx.policy().every, &mut |w, watermark| {
            ctx.checkpoint_in(w, &ScanCursor { watermark })?;
            let tenth = watermark * 10 / len;
            if logged.is_some_and(|t| tenth > t) {
                ctx.log(format!("{}% scanned, up to 0x{watermark:X}, {} hits so far", tenth * 10, ctx.control().snapshot().hits));
            }
            logged = Some(tenth);
            Ok(())
        })
    })?;
    if !summary.completed {
        return Ok(String::new());
    }
    let downgraded = Triage::new(ctx.case()).run(id)?;
    ctx.log(format!("{} hits, {downgraded} inside system files", summary.hits));
    Ok(format!("{} hits in {:.0}s, {downgraded} inside system files", summary.hits, summary.elapsed_secs))
}
