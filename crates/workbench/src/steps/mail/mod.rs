//! Read e-mail: every mail file of the listing (mbox, `.eml`, Outlook Express `.dbx`; live and
//! deleted), then messages carved from free space where the disk index saw text. Messages
//! commit in batches together with the cursor (next mail file and position inside an mbox,
//! then the free-text range and position), so a resumed run continues where the stored
//! messages end. A fresh run clears the disk's stored messages first.

mod carve;
mod files;

use crate::Workbench;
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_case::FoundMessage;
use strata_kernel::Result;

/// Messages kept in memory before a commit is forced.
const BATCH: usize = 500;

#[derive(Debug, Default, Serialize, Deserialize)]
struct MailCursor {
    /// Index of the next mail file to read.
    next: usize,
    /// Position inside that file (an mbox read part way).
    offset: u64,
    /// Mail files done; free space comes next.
    carving: bool,
    /// Free-text range in progress and the next byte to look at.
    range: usize,
    at: u64,
    /// End of the last carved message: header blocks before it are inside it.
    covered: u64,
    files: usize,
    messages: usize,
    carved: usize,
    merged: usize,
}

impl Cursor for MailCursor {
    fn note(&self) -> String {
        match (self.carving, self.offset) {
            (true, _) => format!("free text range {} at {:#x} ({} messages so far)", self.range + 1, self.at, self.messages),
            (false, 0) => format!("mail file {} ({} messages so far)", self.next + 1, self.messages),
            (false, at) => format!("mail file {} at {at:#x} ({} messages so far)", self.next + 1, self.messages),
        }
    }
}

/// Messages waiting for the next commit.
struct Pending<'a> {
    ctx: &'a StepContext<'a>,
    found: Vec<FoundMessage>,
}

impl<'a> Pending<'a> {
    fn new(ctx: &'a StepContext<'a>) -> Self {
        Self { ctx, found: Vec::new() }
    }

    fn push(&mut self, found: FoundMessage) {
        self.found.push(found);
        self.ctx.tick(1);
    }

    /// Commit when a checkpoint is due (or `force`), with `cur` as the resume point.
    fn commit(&mut self, cur: &mut MailCursor, force: bool) -> Result<()> {
        if !force && self.found.len() < BATCH && !self.ctx.tick(0) {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.found);
        let id = self.ctx.evidence();
        cur.messages += batch.len();
        let stored = self.ctx.commit(cur, |w| w.messages(id, &batch))?;
        cur.merged += stored.merged;
        Ok(())
    }
}

pub(super) fn run(ctx: &StepContext<'_>, wb: &Workbench) -> Result<String> {
    let id = ctx.evidence();
    let mut cur = match ctx.cursor::<MailCursor>() {
        Some(cur) => cur,
        None => {
            let fresh = MailCursor::default();
            ctx.commit(&fresh, |w| w.clear_messages(id))?;
            fresh
        }
    };
    let layout = ctx.case().layout(id)?;
    let candidates = files::candidates(&layout, &ctx.case().file_types(id)?);
    let free = wb.index().load(id).map(|idx| carve::free_text(&idx));
    let carve_units: u64 = free.as_ref().map_or(0, |r| r.iter().map(|r| carve::units(r.len())).sum());
    let done = cur.next.min(candidates.len()) as u64 + if cur.carving { carve::units_before(free.as_deref().unwrap_or_default(), cur.range, cur.at) } else { 0 };
    ctx.control().begin_at(done, candidates.len() as u64 + carve_units);
    let mut pending = Pending::new(ctx);
    if !cur.carving {
        files::read_all(ctx, &layout, &candidates, &mut cur, &mut pending)?;
        if ctx.should_stop() {
            pending.commit(&mut cur, true)?;
            return Ok(String::new());
        }
        cur.carving = true;
        pending.commit(&mut cur, true)?;
    }
    match &free {
        Some(ranges) => carve::run(ctx, ranges, &mut cur, &mut pending)?,
        None => ctx.log("no disk index yet (the deep scan builds it): messages in free space were not looked for"),
    }
    pending.commit(&mut cur, true)?;
    if ctx.should_stop() {
        return Ok(String::new());
    }
    let summary = format!(
        "{} from {}, {} carved from free space, {} found more than once",
        super::count(cur.messages - cur.merged, "message", "messages"),
        super::count(cur.files, "mail file", "mail files"),
        cur.carved,
        cur.merged
    );
    ctx.log(summary.clone());
    Ok(summary)
}
