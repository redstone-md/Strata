//! Disk content search as a durable job. The query, the disks and the position reached travel
//! in the cursor; ranges are swept in pieces and the matches of the pieces since the last
//! checkpoint commit together with the position. Results are kept up to
//! [`MAX_RESULTS`](crate::explore::MAX_RESULTS); the search record gets its final state when
//! the job ends (not when the app closes, since it resumes).

use super::sweep::{SweepPos, scan_piece};
use crate::explore::{DiskSearch, MAX_RESULTS};
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_case::SearchResultRow;
use strata_engine::Scanner;
use strata_kernel::{Error, EvidenceId, Result};
use strata_search::{SearchDetector, SearchMatcher, SearchQuery};

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SearchCursor {
    /// Search record the results belong to.
    pub search: i64,
    pub query: Option<SearchQuery>,
    /// Disks to search, in order.
    pub disks: Vec<u32>,
    /// Disks finished.
    pub disk: usize,
    pub pos: SweepPos,
    pub bytes: u64,
    pub stored: usize,
    pub truncated: bool,
}

impl Cursor for SearchCursor {
    fn note(&self) -> String {
        format!("disk {} of {} ({} matches so far)", (self.disk + 1).min(self.disks.len().max(1)), self.disks.len(), self.stored)
    }
}

/// Sweep every disk; false when stopped before the end.
fn sweep(ctx: &StepContext<'_>, cur: &mut SearchCursor, query: &SearchQuery) -> Result<bool> {
    let case = ctx.case();
    let matcher = SearchMatcher::compile(query).map_err(Error::Other)?;
    let scanner = Scanner::new(vec![Arc::new(SearchDetector::new(matcher))]);
    let ranges_of = |id: EvidenceId| DiskSearch::new(case).ranges(id, query.scope);
    let mut total = 0;
    for d in &cur.disks {
        total += ranges_of(EvidenceId::new(*d))?.iter().map(|r| r.len()).sum::<u64>();
    }
    ctx.control().begin_at(cur.bytes, total);
    let piece = ctx.policy().every_bytes.max(1 << 20);
    while let Some(&disk) = cur.disks.get(cur.disk) {
        let id = EvidenceId::new(disk);
        let (source, layout, volumes) = (case.source(id)?, case.layout(id)?, case.record(id)?.volumes);
        let ranges = ranges_of(id)?;
        let mut pending: Vec<SearchResultRow> = Vec::new();
        while let Some((range, start, end)) = cur.pos.next(&ranges, piece) {
            let hits = scan_piece(&scanner, source.as_ref(), range, (start, end), ctx.control())?;
            if ctx.should_stop() {
                ctx.commit(cur, |w| w.search_results(&pending))?;
                return Ok(false);
            }
            let room = MAX_RESULTS.saturating_sub(cur.stored);
            cur.truncated |= hits.len() > room;
            let rows: Vec<_> = hits.iter().take(room).map(|h| DiskSearch::row(cur.search, id, h, source.as_ref(), &layout, &volumes)).collect();
            cur.stored += rows.len();
            pending.extend(rows);
            cur.pos.advance(range, end);
            cur.bytes += end - start;
            ctx.current(&format!("{} at 0x{end:X}", disk_label(id)));
            if cur.truncated || ctx.tick(1) || end - start >= piece {
                let batch = std::mem::take(&mut pending);
                ctx.commit(cur, |w| w.search_results(&batch))?;
            }
            if cur.truncated {
                return Ok(true);
            }
        }
        (cur.disk, cur.pos) = (cur.disk + 1, SweepPos::default());
        let batch = std::mem::take(&mut pending);
        ctx.commit(cur, |w| w.search_results(&batch))?;
        ctx.log(format!("{} searched, {} matches so far", disk_label(id), cur.stored));
    }
    Ok(true)
}

fn disk_label(id: EvidenceId) -> String {
    format!("disk {id}")
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let mut cur: SearchCursor = ctx.cursor().ok_or_else(|| Error::Other("search job without its query".into()))?;
    let query = cur.query.clone().ok_or_else(|| Error::Other("search job without its query".into()))?;
    let finished = sweep(ctx, &mut cur, &query);
    let state = match &finished {
        Err(e) => format!("failed: {e}"),
        Ok(false) if ctx.interrupted() => return Ok(String::new()),
        Ok(false) => "cancelled".into(),
        Ok(true) => "done".into(),
    };
    ctx.case().finish_search(cur.search, &state, cur.truncated)?;
    finished?;
    let more = if cur.truncated { format!(" (first {MAX_RESULTS}; refine the query to see the rest)") } else { String::new() };
    Ok(format!("{} matches{more}", cur.stored))
}
