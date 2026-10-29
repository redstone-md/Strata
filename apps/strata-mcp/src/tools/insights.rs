//! What the date analyser concluded: accounts on services merged from every trace, and ranked
//! leads explained in plain sentences.

use super::findings::Finding;
use super::timeline::Event;
use crate::StrataServer;
use crate::format::{Page, Paging, Reply, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{Account, AccountQuery, AccountRow, AccountSource, Lead, Period, ServiceGroup, SourceRef, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccountsParams {
    /// Part of the service name or the identifier (any case).
    pub text: Option<String>,
    /// Only one section: crypto, money, mail, cloud, social, games, shopping, other.
    pub section: Option<String>,
    /// `used` (default): accounts some trace shows the owner used (saved password, mail client,
    /// Windows user, cookie, form input...). `seen`: names only seen in data (mail headers,
    /// pages, free space), most promising first.
    pub standing: Option<String>,
    /// With `standing = seen`: also addresses found only in dumps and mailing lists.
    pub include_bulk: bool,
    /// Only accounts on services that hold funds (exchanges, web wallets, pools...).
    pub funds_only: bool,
    /// Also return every trace (finding, event or file) behind each account. Default false.
    pub traces: bool,
    /// Period of interest, `2011`, `2011-06` or `2011-06-14`; accounts seen outside it are left
    /// out (undated ones stay).
    pub from: Option<String>,
    pub to: Option<String>,
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LeadsParams {
    /// Also return the findings and timeline events each lead points at. Default false (ids only).
    pub resolve: bool,
    /// Rows per page, default 50, at most 500, best first.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
struct AccountOut {
    /// Stable key `service|identifier`; leads refer to accounts by it.
    key: String,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_kind: Option<String>,
    /// crypto, money, mail, cloud, social, games, shopping, other.
    section: String,
    identifier: String,
    /// `e-mail`, `login`, `user id`, `nickname`, `phone`.
    kind: String,
    /// `used` by the owner, only `seen` in data, or `bulk` (only in dumps and lists).
    standing: String,
    /// 0..1 evidence that the owner used it; kinds of trace combine, repeats count once.
    strength: f32,
    /// Why it is listed, strongest first (`saved password`, `mail client account`...).
    why: Vec<String>,
    password_saved: bool,
    holds_funds: bool,
    first_seen: Option<String>,
    last_seen: Option<String>,
    disks: Vec<u32>,
    /// Traces behind the account (for a bare sighting: times found).
    traces_count: u64,
    /// Times the address was also found byte-level on the disks.
    #[serde(skip_serializing_if = "is_zero")]
    sightings: u64,
    /// A bare byte-level sighting, not an account resolved from artefacts.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    sighting_only: bool,
    /// Keys of accounts with the same identifier elsewhere (with `traces`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    linked: Vec<String>,
    /// The traces that name the account (with `traces`).
    #[serde(skip_serializing_if = "Option::is_none")]
    sources: Option<Vec<Source>>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Serialize)]
struct Source {
    disk: u32,
    /// Kind of trace (`saved password`, `in mail headers`, `found in data`...).
    trace: String,
    detail: String,
    at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

impl Source {
    fn of(s: &AccountSource) -> Self {
        let (finding_id, event_id, file) = match &s.origin {
            SourceRef::Hit(id) => (Some(*id), None, None),
            SourceRef::Event(id) => (None, Some(*id), None),
            SourceRef::File(path) => (None, None, Some(path.clone())),
        };
        Self { disk: s.evidence.get(), trace: s.trace.label().to_string(), detail: s.detail.clone(), at: s.at.map(time), finding_id, event_id, file }
    }
}

impl AccountOut {
    fn of(r: &AccountRow, account: Option<&Account>) -> Self {
        Self {
            key: r.key.clone(),
            service: r.service.clone(),
            service_kind: r.service_kind.clone(),
            section: r.group.id().to_string(),
            identifier: r.identifier.clone(),
            kind: r.kind.clone(),
            standing: r.standing.label().to_string(),
            strength: (r.strength * 100.0).round() / 100.0,
            why: r.reasons.iter().map(|k| k.label().to_string()).collect(),
            password_saved: r.secret,
            holds_funds: r.holds_funds(),
            first_seen: r.first_seen.map(time),
            last_seen: r.last_seen.map(time),
            disks: r.disks.iter().map(|d| d.get()).collect(),
            traces_count: r.traces,
            sightings: r.mentions,
            sighting_only: r.mention_only,
            linked: account.map(|a| a.linked().to_vec()).unwrap_or_default(),
            sources: account.map(|a| a.sources().iter().map(Source::of).collect()),
        }
    }
}

#[derive(Serialize)]
struct LeadRow {
    id: String,
    rule: String,
    title: String,
    /// 0..100.
    score: f32,
    /// Facts and the conclusion drawn from them, one sentence each.
    explanation: Vec<String>,
    /// The period the lead is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<[String; 2]>,
    disks: Vec<u32>,
    finding_ids: Vec<i64>,
    event_ids: Vec<i64>,
    addresses: Vec<String>,
    /// Account keys (see `accounts`).
    accounts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<Vec<Finding>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    events: Option<Vec<Event>>,
}

impl LeadRow {
    fn of(wb: &Workbench, l: &Lead, resolve: bool) -> Reply<Self> {
        let (findings, events) = if resolve {
            let hits = wb.lead_hits(l).map_err(fail)?;
            let events = wb.lead_events(l).map_err(fail)?;
            (
                Some(hits.iter().map(|h| Finding::of(h, false)).collect()),
                Some(events.iter().map(|e| Event::of(Some(e.id), e.evidence.get(), &e.event)).collect()),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            id: l.id.clone(),
            rule: l.rule.label().to_string(),
            title: l.title.clone(),
            score: l.score.round(),
            explanation: l.explanation.clone(),
            window: l.window.map(|(from, to)| [time(from), time(to)]),
            disks: l.evidence.iter().map(|d| d.get()).collect(),
            finding_ids: l.hits().collect(),
            event_ids: l.events().collect(),
            addresses: l.addresses().map(str::to_string).collect(),
            accounts: l.accounts().map(str::to_string).collect(),
            findings,
            events,
        })
    }
}

fn accounts(wb: &Workbench, p: AccountsParams) -> Reply<Page<AccountOut>> {
    let seen = match p.standing.as_deref().map(str::trim) {
        None | Some("") | Some("used") => false,
        Some("seen") => true,
        Some(other) => return Err(format!("standing must be used or seen, not {other:?}")),
    };
    let group = match p.section.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(ServiceGroup::from_id(s).ok_or_else(|| format!("unknown section {s:?}; use crypto, money, mail, cloud, social, games, shopping or other"))?),
        None => None,
    };
    let period = match (p.from.as_deref(), p.to.as_deref()) {
        (None, None) => None,
        (from, to) => Some(Period::parse(from.unwrap_or(""), to.unwrap_or("")).ok_or_else(|| "from / to must look like 2011, 2011-06 or 2011-06-14".to_string())?),
    };
    let limit = Paging::LIST.limit(p.limit);
    let mut query = AccountQuery { seen, include_bulk: p.include_bulk, group, text: p.text, period, ..Default::default() };
    if p.funds_only {
        // Fund-holding services are a few catalogued kinds: filter, then page.
        let rows: Vec<AccountRow> = wb.account_rows(&query).map_err(fail)?.into_iter().filter(AccountRow::holds_funds).collect();
        return Page::slice(rows, p.offset, limit).try_map(|r| row_out(wb, &r, p.traces));
    }
    query.limit = limit + 1;
    query.offset = p.offset;
    let mut page = Page::probed(wb.account_rows(&query).map_err(fail)?, p.offset, limit);
    query.limit = 0;
    page.total = Some(wb.account_count(&query).map_err(fail)? as usize);
    page.try_map(|r| row_out(wb, &r, p.traces))
}

fn row_out(wb: &Workbench, r: &AccountRow, traces: bool) -> Reply<AccountOut> {
    let account = if traces && !r.mention_only { wb.account(&r.key).map_err(fail)? } else { None };
    Ok(AccountOut::of(r, account.as_ref()))
}

fn leads(wb: &Workbench, p: LeadsParams) -> Reply<Page<LeadRow>> {
    Page::slice(wb.leads().map_err(fail)?, p.offset, Paging::LIST.limit(p.limit)).try_map(|l| LeadRow::of(wb, &l, p.resolve))
}

#[tool_router(router = insight_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Who the owner was and where they had accounts that may hold money or wallet backups. By default \
        lists the accounts the owner used (some trace shows use: saved browser password, mail client account, Windows user, \
        mailbox owner, sent mail, program settings, form input, login cookie...), strongest evidence first, one row per \
        service and login merged across disks, with the reasons (`why`), whether a password is saved, first and last seen \
        and disks. Sections: crypto, money (banks, e-money), mail, cloud (storage, notes, password vaults), social \
        (messengers, social networks), games, shopping, other. `standing = seen` lists names only seen in data (mail headers, \
        pages, free space); add `include_bulk` for addresses found only in dumps and lists. `traces = true` adds every \
        finding, event or file behind each account."
    )]
    pub async fn accounts(&self, Parameters(p): Parameters<AccountsParams>) -> Reply<String> {
        self.query(move |wb| accounts(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Ranked leads from the date analyser, best first: hypotheses such as on-chain activity of a found key \
        lining up with crypto activity in the timeline, a wallet file written while the user was active on a service, a \
        seed saved right after a wallet install, accounts worth checking for funds. Each has a score (0-100), a plain-sentence \
        explanation and the ids of the findings, events, addresses and accounts it rests on."
    )]
    pub async fn leads(&self, Parameters(p): Parameters<LeadsParams>) -> Reply<String> {
        self.query(move |wb| leads(wb, p)).await
    }
}
