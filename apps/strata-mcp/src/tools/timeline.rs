//! The timeline: dated traces from browsers, registry, Windows and Linux artefacts, mail and
//! filesystems, activity per day, and host facts (computer name, users, devices).

use crate::StrataServer;
use crate::format::{Bound, Page, Paging, Reply, date_param, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{EventQuery, TimelineEvent, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TimelineParams {
    /// Start, inclusive: YYYY, YYYY-MM, YYYY-MM-DD or YYYY-MM-DD HH:MM:SS (UTC).
    pub from: Option<String>,
    /// End, inclusive of the named period: `to=2012-03` runs through the end of March 2012.
    pub to: Option<String>,
    /// Part of the title or source path (any case).
    pub text: Option<String>,
    /// Only events tagged as crypto-related (wallet software, exchanges, faucets, keys...).
    pub crypto_only: bool,
    /// Include filesystem MACB times (file created/modified/accessed), usually the bulk of a
    /// timeline. Default false.
    pub include_filesystem: bool,
    /// Only this disk id.
    pub disk: Option<u32>,
    /// Events per page, default 100, at most 1000, oldest first.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ActivityParams {
    /// Only this disk id.
    pub disk: Option<u32>,
    /// First day, as in `timeline`.
    pub from: Option<String>,
    /// Last day, as in `timeline`.
    pub to: Option<String>,
    /// Only days with crypto-related events.
    pub crypto_only: bool,
    /// Days per page, default 100, at most 1000.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct HostFactsParams {
    /// Only this disk id.
    pub disk: Option<u32>,
}

#[derive(Serialize)]
pub(crate) struct Event {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    at: String,
    disk: u32,
    kind: String,
    title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    /// Parser that read it (`chrome.history`, `registry.userassist`, `fs.ntfs`...).
    artifact: String,
    /// File the event was read from.
    path: String,
    /// That file was deleted, orphaned or carved.
    source_deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

impl Event {
    pub(crate) fn of(id: Option<i64>, disk: u32, e: &TimelineEvent) -> Self {
        Self {
            id,
            at: time(e.at()),
            disk,
            kind: format!("{:?}", e.kind()),
            title: e.title().to_string(),
            detail: e.detail().to_string(),
            artifact: e.source().artifact.clone(),
            path: e.source().path.clone(),
            source_deleted: e.source().deleted,
            actor: e.actor().map(str::to_string),
            tags: e.tags().to_vec(),
        }
    }
}

#[derive(Serialize)]
struct Day {
    day: String,
    /// Events that day, filesystem times not counted.
    events: u64,
    crypto: u64,
}

#[derive(Serialize)]
struct Fact {
    disk: u32,
    key: String,
    value: String,
    artifact: String,
    source: String,
}

fn timeline(wb: &Workbench, p: TimelineParams) -> Reply<Page<Event>> {
    let limit = Paging::LONG.limit(p.limit);
    let q = EventQuery {
        evidence: super::disk(p.disk),
        from: date_param(p.from.as_deref(), Bound::Start)?,
        to: date_param(p.to.as_deref(), Bound::End)?,
        text: p.text,
        crypto_only: p.crypto_only,
        skip_filesystem: !p.include_filesystem,
        limit: limit + 1,
        offset: p.offset,
    };
    let rows = wb.events(&q).map_err(fail)?;
    Ok(Page::probed(rows, p.offset, limit).map(|(disk, e)| Event::of(None, disk.get(), &e)))
}

fn activity(wb: &Workbench, p: ActivityParams) -> Reply<Page<Day>> {
    let from = date_param(p.from.as_deref(), Bound::Start)?;
    let to = date_param(p.to.as_deref(), Bound::End)?;
    let days: Vec<Day> = wb
        .events_per_day(super::disk(p.disk))
        .map_err(fail)?
        .into_iter()
        .filter(|(day, _, crypto)| from.is_none_or(|f| *day >= f) && to.is_none_or(|t| *day < t) && (!p.crypto_only || *crypto > 0))
        .map(|(day, events, crypto)| Day { day: time(day).chars().take(10).collect(), events, crypto })
        .collect();
    Ok(Page::slice(days, p.offset, Paging::LONG.limit(p.limit)))
}

fn facts(wb: &Workbench, p: HostFactsParams) -> Reply<Vec<Fact>> {
    Ok(wb
        .host_facts(super::disk(p.disk))
        .map_err(fail)?
        .into_iter()
        .map(|f| Fact { disk: f.evidence.get(), key: f.key, value: f.value, artifact: f.artifact, source: f.source })
        .collect())
}

#[tool_router(router = timeline_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Timeline events, oldest first: URLs visited, downloads, searches, programs run and installed, documents \
        opened, USB devices, logins, accounts seen, form input, cookies, mail, wallet activity, system logs; filesystem \
        times only when asked. Filter by date range, text, disk or crypto relevance."
    )]
    pub async fn timeline(&self, Parameters(p): Parameters<TimelineParams>) -> Reply<String> {
        self.query(move |wb| timeline(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Number of timeline events per UTC day (filesystem times not counted) and how many were crypto-related. \
        Cheap way to find the active periods before reading `timeline`."
    )]
    pub async fn activity_per_day(&self, Parameters(p): Parameters<ActivityParams>) -> Reply<String> {
        self.query(move |wb| activity(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Host facts read from the disks: computer name, Windows version, user profiles, USB devices, wallet \
        data folders and similar, each with the artefact it came from."
    )]
    pub async fn host_facts(&self, Parameters(p): Parameters<HostFactsParams>) -> Reply<String> {
        self.query(move |wb| facts(wb, p)).await
    }
}
