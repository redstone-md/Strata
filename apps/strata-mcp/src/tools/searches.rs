//! Whole-disk content searches run from the app and their stored matches. New searches are
//! not started here: a search reads the whole disk and belongs to the app's job queue.

use crate::StrataServer;
use crate::format::{Page, Paging, Reply, fail, unix_time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{SearchRecord, SearchResultRow, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SearchesParams {
    /// A search id to read its matches; without it the stored searches are listed, newest first.
    pub search_id: Option<i64>,
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
struct SearchOut {
    id: i64,
    summary: String,
    /// The query as the app stored it (patterns, encodings, scope).
    query: serde_json::Value,
    created: Option<String>,
    /// `running`, `done`, `cancelled` or `failed: ...`.
    state: String,
    results: u64,
    /// The result cap was reached; more matches exist on the disk.
    truncated: bool,
}

impl SearchOut {
    fn of(r: SearchRecord) -> Self {
        let query = serde_json::from_str(&r.query).unwrap_or(serde_json::Value::String(r.query));
        Self { id: r.id, summary: r.summary, query, created: unix_time(r.created_at), state: r.state, results: r.results, truncated: r.truncated }
    }
}

#[derive(Serialize)]
struct Match {
    disk: u32,
    /// Byte offset on the disk.
    offset: u64,
    length: u32,
    encoding: String,
    /// The matched text.
    text: String,
    /// Text around the match, control bytes replaced.
    preview: String,
    /// `live`, `deleted`, `orphan`, `unallocated`, `deleted partition` or `outside volumes`.
    location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_offset: Option<u64>,
}

impl Match {
    fn of(r: SearchResultRow) -> Self {
        let text = r.preview.chars().skip(r.match_from as usize).take(r.match_to.saturating_sub(r.match_from) as usize).collect();
        Self {
            disk: r.evidence.get(),
            offset: r.offset,
            length: r.len,
            encoding: r.encoding,
            text,
            preview: r.preview,
            location: r.location,
            volume: r.volume,
            file_path: r.file_path,
            file_state: r.file_state,
            file_offset: r.file_offset,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum SearchesOut {
    List(Page<SearchOut>),
    Results { search: SearchOut, matches: Page<Match> },
}

fn searches(wb: &Workbench, p: SearchesParams) -> Reply<SearchesOut> {
    let limit = Paging::LIST.limit(p.limit);
    let Some(id) = p.search_id else {
        let all = wb.searches(p.offset + limit + 1).map_err(fail)?;
        let rows: Vec<SearchRecord> = all.into_iter().skip(p.offset).collect();
        return Ok(SearchesOut::List(Page::probed(rows, p.offset, limit).map(SearchOut::of)));
    };
    let record = wb.search_record(id).map_err(fail)?.ok_or_else(|| format!("no search with id {id}"))?;
    let rows = wb.search_results(id, p.offset, limit + 1).map_err(fail)?;
    Ok(SearchesOut::Results { search: SearchOut::of(record), matches: Page::probed(rows, p.offset, limit).map(Match::of) })
}

#[tool_router(router = search_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Whole-disk content searches the user ran in the app (text, hex or regex in several encodings) and their \
        matches: offset, matched text with context, and whether each sits in a live file, a deleted file, free space or a \
        deleted partition. Without search_id lists the searches; with it pages through one search's matches. Cannot start \
        new searches."
    )]
    pub async fn searches(&self, Parameters(p): Parameters<SearchesParams>) -> Reply<String> {
        self.query(move |wb| searches(wb, p)).await
    }
}
