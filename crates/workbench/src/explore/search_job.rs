//! Disk content search as a background job: the query's matcher runs through the scan engine
//! over the ranges its scope selects; every match is attributed to volume and file and stored
//! with the bytes around it.

use std::sync::Arc;
use strata_case::{Case, EvidenceLayout, SearchResultRow};
use strata_engine::{ScanControl, Scanner};
use strata_fs::EntryState;
use strata_kernel::scan::Hit;
use strata_kernel::{ByteRange, EvidenceId, Result};
use strata_search::{CONTEXT, Scope, SearchDetector, SearchMatcher, SearchQuery, Snippet};
use strata_volume::{Volume, VolumeOrigin};

/// Results kept per search; the rest is counted as "more".
pub const MAX_RESULTS: usize = 100_000;

/// Where a match sits, as the results table labels it.
pub fn location(file_state: Option<EntryState>, volume: Option<&Volume>) -> &'static str {
    if volume.is_some_and(|v| v.origin == VolumeOrigin::Recovered) {
        return "deleted partition";
    }
    match file_state {
        Some(EntryState::Allocated) => "live",
        Some(EntryState::Deleted) => "deleted",
        Some(EntryState::Orphan) => "orphan",
        None => "unallocated",
    }
}

pub struct DiskSearch<'a> {
    case: &'a Case,
}

/// How one disk's search went.
pub struct DiskOutcome {
    pub stored: usize,
    pub truncated: bool,
}

impl<'a> DiskSearch<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Absolute disk ranges a scope covers.
    pub fn ranges(&self, id: EvidenceId, scope: Scope) -> Result<Vec<ByteRange>> {
        let len = self.case.source(id)?.len();
        Ok(match scope {
            Scope::WholeDisk => vec![ByteRange::new(0, len)],
            Scope::Unallocated => self.case.layout(id)?.free_space(len),
            Scope::DeletedFiles => self.case.layout(id)?.deleted_content(),
            Scope::Volume(n) => self.case.record(id)?.volumes.iter().filter(|v| v.index == n).map(|v| v.range).collect(),
        })
    }

    /// Search one disk; at most `budget` results are stored.
    pub fn run(&self, search: i64, id: EvidenceId, query: &SearchQuery, budget: usize, control: &ScanControl) -> Result<DiskOutcome> {
        let matcher = SearchMatcher::compile(query).map_err(strata_kernel::Error::Other)?;
        let scanner = Scanner::new(vec![Arc::new(SearchDetector::new(matcher))]);
        let source = self.case.source(id)?;
        let layout = self.case.layout(id)?;
        let volumes = self.case.record(id)?.volumes;
        let ranges = self.ranges(id, query.scope)?;
        let mut outcome = DiskOutcome { stored: 0, truncated: false };
        let mut failure = None;
        scanner.run_ranges(source.as_ref(), &ranges, control, |hits| {
            if failure.is_some() || outcome.truncated {
                return;
            }
            let room = budget.saturating_sub(outcome.stored);
            if hits.len() > room {
                outcome.truncated = true;
                control.cancel();
            }
            let rows: Vec<SearchResultRow> =
                hits.iter().take(room).map(|h| Self::row(search, id, h, source.as_ref(), &layout, &volumes)).collect();
            match self.case.store_search_results(&rows) {
                Ok(n) => outcome.stored += n,
                Err(e) => {
                    failure = Some(e);
                    control.cancel();
                }
            }
        })?;
        failure.map_or(Ok(outcome), Err)
    }

    fn row(search: i64, id: EvidenceId, h: &Hit, disk: &dyn strata_source::BlockSource, layout: &EvidenceLayout, volumes: &[Volume]) -> SearchResultRow {
        let encoding = SearchDetector::encoding_of(h);
        let context_start = h.offset.saturating_sub(CONTEXT as u64);
        let lead = (h.offset - context_start) as usize;
        let context = disk.read_vec(context_start, lead + h.len as usize + CONTEXT).unwrap_or_default();
        let snippet = Snippet::render(&context, lead, h.len as usize, encoding);
        let a = layout.attribute(h.offset);
        let volume = a.volume.and_then(|i| volumes.iter().find(|v| v.index == i));
        SearchResultRow {
            search_id: search,
            evidence: id,
            offset: h.offset,
            len: h.len,
            encoding: encoding.name().to_string(),
            context,
            context_start,
            preview: snippet.preview,
            match_from: snippet.match_from,
            match_to: snippet.match_to,
            volume: a.volume,
            location: location(a.file.as_ref().map(|f| f.state), volume).to_string(),
            file_path: a.file.as_ref().map(|f| f.path.clone()),
            file_state: a.file.as_ref().map(|f| format!("{:?}", f.state)),
            file_offset: a.file.as_ref().map(|f| f.file_offset),
        }
    }
}
