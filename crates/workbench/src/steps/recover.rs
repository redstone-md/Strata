//! Copying selected files out of the evidence as a durable job. The selection and the target
//! folder travel in the cursor; a checkpoint follows every item, so a resumed job continues
//! with the next one; the item an interrupted run may have been writing is written again over
//! its earlier copy.

use crate::explore::recovery::{FileRecovery, RecoverySummary};
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strata_kernel::{Error, Result};

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct RecoverCursor {
    pub volume: u32,
    /// Entry indexes of the volume (folders expand to everything below them).
    pub selection: Vec<usize>,
    pub dest: PathBuf,
    /// Items finished, in recovery order.
    pub done: usize,
    pub summary: RecoverySummary,
    /// Runs started; more than one means the job was interrupted before.
    pub runs: u32,
}

impl Cursor for RecoverCursor {
    fn note(&self) -> String {
        format!("item {} ({} files written so far)", self.done + 1, self.summary.files)
    }
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let mut cur: RecoverCursor = ctx.cursor().ok_or_else(|| Error::Other("recovery job without its selection".into()))?;
    let (selection, dest) = (cur.selection.clone(), cur.dest.clone());
    let resume = (cur.done, cur.summary, cur.runs > 0);
    cur.runs += 1;
    ctx.commit(&cur, |_| Ok(()))?;
    let summary = FileRecovery::new(ctx.case()).run((ctx.evidence(), cur.volume), &selection, &dest, ctx.control(), resume, &mut |done, s| {
        (cur.done, cur.summary) = (done, *s);
        ctx.commit(&cur, |_| Ok(()))
    })?;
    ctx.log(summary.describe());
    Ok(summary.describe())
}
