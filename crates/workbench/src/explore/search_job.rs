//! Disk content search: which ranges a scope covers and how a match becomes a result row
//! (attributed to volume and file, with the bytes around it). The resumable job that runs the
//! matcher over those ranges is the Search step.

use strata_case::{Case, EvidenceLayout, SearchResultRow};
use strata_fs::EntryState;
use strata_kernel::scan::Hit;
use strata_kernel::{ByteRange, EvidenceId, Result};
use strata_search::{CONTEXT, Scope, SearchDetector, Snippet};
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

    pub(crate) fn row(search: i64, id: EvidenceId, h: &Hit, disk: &dyn strata_source::BlockSource, layout: &EvidenceLayout, volumes: &[Volume]) -> SearchResultRow {
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
