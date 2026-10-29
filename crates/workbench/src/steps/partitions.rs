//! Recover deleted partitions from the structures the deep scan found. Idempotent (volumes
//! already known are skipped, file rows already stored are kept), so the checkpoint only
//! records that it finished.

use crate::explore::PartitionRecovery;
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_kernel::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
struct PartitionsCursor {
    summary: Option<String>,
}

impl Cursor for PartitionsCursor {
    fn note(&self) -> String {
        match self.summary {
            Some(_) => "nothing left".into(),
            None => "the beginning (the step is idempotent)".into(),
        }
    }
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    if let Some(done) = ctx.cursor::<PartitionsCursor>().and_then(|c| c.summary) {
        return Ok(done);
    }
    ctx.control().begin_items(1);
    ctx.current("partition structures found by the scan");
    let report = PartitionRecovery::new(ctx.case()).run(ctx.evidence())?;
    let summary = report.describe();
    ctx.control().item_done();
    ctx.commit(&PartitionsCursor { summary: Some(summary.clone()) }, |_| Ok(()))?;
    ctx.log(summary.clone());
    Ok(summary)
}
