//! Deep scan: every detector over every byte, resumed from the stored watermark. Hits, the
//! watermark and the job checkpoint commit together.

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

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let scanner = Scanner::new(DetectorCatalog::all());
    let summary = ctx.case().scan_with(id, &scanner, ctx.control(), ctx.policy().every, &mut |w, watermark| {
        ctx.checkpoint_in(w, &ScanCursor { watermark })
    })?;
    if !summary.completed {
        return Ok(String::new());
    }
    let downgraded = Triage::new(ctx.case()).run(id)?;
    ctx.log(format!("{} hits, {downgraded} inside system files", summary.hits));
    Ok(format!("{} hits in {:.0}s, {downgraded} inside system files", summary.hits, summary.elapsed_secs))
}
