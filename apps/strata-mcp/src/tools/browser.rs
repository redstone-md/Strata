//! Browser history as its own subject: profiles per disk, visited sites with the catalogued
//! service behind them, and the history, searches, downloads, saved logins and form values
//! and cookies of every browser the parsers read (Chromium family, Firefox, Opera, IE).

use crate::StrataServer;
use crate::format::{Bound, Page, Paging, Reply, date_param, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{
    BrowserFilter, BrowserQuery, BrowserRow, BrowserSegment, BrowserSpan, CookieSite, ProfileKey, ProfileSummary, Service, SiteSummary, Workbench,
};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BrowserHistoryParams {
    /// `profiles` (per disk and browser profile: counts, time span, top sites), `sites` (visited
    /// hosts with visit counts and the known service, crypto-related first), `history` (default),
    /// `searches`, `downloads`, `logins` (saved logins, their use and form / autofill values) or
    /// `cookies` (grouped by the host that set them).
    pub view: Option<String>,
    /// Only this disk id.
    pub disk: Option<u32>,
    /// Only this browser profile: its `folder` as `profiles` lists it (needs `disk`).
    pub profile: Option<String>,
    /// Start date: YYYY, YYYY-MM, YYYY-MM-DD or YYYY-MM-DD HH:MM:SS (UTC).
    pub from: Option<String>,
    /// End date, inclusive of the period it names (`2012` covers all of 2012).
    pub to: Option<String>,
    /// Part of the URL, search term, page title, form value or source path.
    pub text: Option<String>,
    /// Only rows on this host (`example.com` also matches `www.example.com`).
    pub site: Option<String>,
    /// Only crypto-related rows and sites (exchanges, wallets, faucets, pools, forums...).
    pub crypto_only: bool,
    /// Rows per page, default 100, at most 1000.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
struct Span {
    first: String,
    last: String,
}

impl Span {
    fn of(s: BrowserSpan) -> Self {
        Self { first: time(s.first), last: time(s.last) }
    }
}

#[derive(Serialize)]
struct Known {
    service: &'static str,
    kind: &'static str,
}

impl Known {
    fn of(s: Option<Service>) -> Option<Self> {
        s.map(|s| Self { service: s.name, kind: s.kind.label() })
    }
}

#[derive(Serialize)]
struct Profile {
    disk: u32,
    browser: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    /// Folder of the profile; pass it as `profile` to narrow the other views.
    folder: String,
    visits: u64,
    deleted_visits: u64,
    searches: u64,
    downloads: u64,
    logins_and_forms: u64,
    cookies: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<Span>,
    top_sites: Vec<(String, u64)>,
}

impl Profile {
    fn of(p: ProfileSummary) -> Self {
        let n = |s| p.count(s);
        Self {
            disk: p.key.evidence.get(),
            browser: p.key.browser(),
            user: p.key.user().map(str::to_string),
            visits: n(BrowserSegment::History),
            searches: n(BrowserSegment::Searches),
            downloads: n(BrowserSegment::Downloads),
            logins_and_forms: n(BrowserSegment::Logins),
            cookies: n(BrowserSegment::Cookies),
            deleted_visits: p.deleted_visits,
            span: p.span.map(Span::of),
            top_sites: p.top_sites,
            folder: p.key.dir,
        }
    }
}

#[derive(Serialize)]
struct Site {
    host: String,
    visits: u64,
    crypto: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    known: Option<Known>,
    deleted_visits: u64,
    disks: Vec<u32>,
    span: Span,
}

impl Site {
    fn of(s: SiteSummary) -> Self {
        Self {
            crypto: s.is_crypto(),
            known: Known::of(s.service),
            host: s.host,
            visits: s.visits,
            deleted_visits: s.deleted,
            disks: s.disks.iter().map(|d| d.get()).collect(),
            span: Span::of(s.span),
        }
    }
}

#[derive(Serialize)]
struct CookieHost {
    host: String,
    events: u64,
    names: Vec<String>,
    crypto: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    known: Option<Known>,
    disks: Vec<u32>,
    span: Span,
}

impl CookieHost {
    fn of(c: CookieSite) -> Self {
        Self {
            crypto: c.is_crypto(),
            known: Known::of(c.service),
            host: c.host,
            events: c.events,
            names: c.names,
            disks: c.disks.iter().map(|d| d.get()).collect(),
            span: Span::of(c.span),
        }
    }
}

#[derive(Serialize)]
struct Row {
    at: String,
    disk: u32,
    browser: &'static str,
    kind: String,
    /// URL, search term, downloaded file, `user @ site` or `field = value`.
    title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    /// Read from a deleted file, a freed database row or carved bytes.
    deleted: bool,
    artifact: String,
    path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

impl Row {
    fn of(r: BrowserRow) -> Self {
        let e = &r.event;
        Self {
            at: time(e.at()),
            disk: r.evidence.get(),
            browser: r.profile().browser(),
            kind: format!("{:?}", e.kind()),
            title: e.title().to_string(),
            detail: e.detail().to_string(),
            deleted: r.deleted(),
            artifact: e.source().artifact.clone(),
            path: e.source().path.clone(),
            tags: e.tags().to_vec(),
        }
    }
}

/// What a view returns.
#[derive(Serialize)]
#[serde(untagged)]
enum View {
    Profiles(Page<Profile>),
    Sites(Page<Site>),
    Cookies(Page<CookieHost>),
    Rows(Page<Row>),
}

fn filter(wb: &Workbench, p: &BrowserHistoryParams) -> Reply<BrowserFilter> {
    let mut f = BrowserFilter {
        evidence: super::disk(p.disk),
        from: date_param(p.from.as_deref(), Bound::Start)?,
        to: date_param(p.to.as_deref(), Bound::End)?,
        text: p.text.clone().filter(|t| !t.trim().is_empty()),
        site: p.site.clone().filter(|t| !t.trim().is_empty()),
        crypto_only: p.crypto_only,
        profile: None,
    };
    if let Some(folder) = p.profile.as_deref().filter(|f| !f.trim().is_empty()) {
        let disk = f.evidence.ok_or("`profile` needs `disk`")?;
        let profiles = wb.browser_overview(&BrowserFilter { evidence: Some(disk), ..BrowserFilter::default() }).map_err(fail)?.profiles;
        let key: ProfileKey =
            profiles.into_iter().map(|p| p.key).find(|k| k.dir == folder).ok_or_else(|| format!("no browser profile {folder:?} on disk {}", disk.get()))?;
        f.profile = Some(key);
    }
    Ok(f)
}

fn browser_history(wb: &Workbench, p: BrowserHistoryParams) -> Reply<View> {
    let f = filter(wb, &p)?;
    let limit = Paging::LONG.limit(p.limit);
    let view = p.view.as_deref().unwrap_or("history").trim().to_ascii_lowercase();
    Ok(match view.as_str() {
        "profiles" => View::Profiles(Page::slice(wb.browser_overview(&f).map_err(fail)?.profiles, p.offset, limit).map(Profile::of)),
        "sites" => View::Sites(Page::slice(wb.browser_overview(&f).map_err(fail)?.sites, p.offset, limit).map(Site::of)),
        "cookies" => View::Cookies(Page::slice(wb.browser_cookie_sites(&f).map_err(fail)?, p.offset, limit).map(CookieHost::of)),
        name => {
            let segment = BrowserSegment::from_name(name)
                .ok_or_else(|| format!("unknown view {name:?}; use profiles, sites, history, searches, downloads, logins or cookies"))?;
            let q = BrowserQuery { filter: f, segment, limit: limit + 1, offset: p.offset };
            let rows = wb.browser_rows(&q).map_err(fail)?;
            let mut page = Page::probed(rows, p.offset, limit).map(Row::of);
            page.total = Some(wb.browser_count(&q).map_err(fail)? as usize);
            View::Rows(page)
        }
    })
}

#[tool_router(router = browser_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Browser history read from the disks (Chrome and other Chromium browsers, Firefox, Opera, Internet \
        Explorer index.dat and typed URLs, deleted rows recovered from history databases). Views: profiles (per disk and \
        browser profile: visits, searches, downloads, logins, cookies, time span, top sites), sites (visited hosts with the \
        known service behind them, crypto-related first), history, searches, downloads, logins (saved logins and form / \
        autofill values) and cookies (by host). Filter by disk, profile, date range, text, site or crypto relevance."
    )]
    pub async fn browser_history(&self, Parameters(p): Parameters<BrowserHistoryParams>) -> Reply<String> {
        self.query(move |wb| browser_history(wb, p)).await
    }
}
