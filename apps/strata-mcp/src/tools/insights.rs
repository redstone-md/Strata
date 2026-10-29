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
use strata_workbench::{Account, AccountSource, Lead, SourceRef, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccountsParams {
    /// Part of the service name or the identifier (any case).
    pub text: Option<String>,
    /// Only accounts on services that hold funds (exchanges, web wallets, pools...).
    pub funds_only: bool,
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
struct AccountRow {
    /// Stable key `service|identifier`; leads refer to accounts by it.
    key: String,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_kind: Option<String>,
    identifier: String,
    /// `e-mail`, `login`, `user id`, `nickname`, `phone`.
    kind: String,
    holds_funds: bool,
    confidence: f32,
    first_seen: Option<String>,
    last_seen: Option<String>,
    disks: Vec<u32>,
    /// Keys of accounts with the same identifier elsewhere.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    linked: Vec<String>,
    /// The traces that name the account.
    sources: Vec<Source>,
}

#[derive(Serialize)]
struct Source {
    disk: u32,
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
        Self { disk: s.evidence.get(), detail: s.detail.clone(), at: s.at.map(time), finding_id, event_id, file }
    }
}

impl AccountRow {
    fn of(a: &Account) -> Self {
        Self {
            key: a.key().to_string(),
            service: a.service().to_string(),
            service_kind: a.service_kind().map(|k| format!("{k:?}")),
            identifier: a.identifier().to_string(),
            kind: a.kind().label().to_string(),
            holds_funds: a.holds_funds(),
            confidence: (a.confidence() * 100.0).round() / 100.0,
            first_seen: a.first_seen().map(time),
            last_seen: a.last_seen().map(time),
            disks: a.disks().iter().map(|d| d.get()).collect(),
            linked: a.linked().to_vec(),
            sources: a.sources().iter().map(Source::of).collect(),
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

fn accounts(wb: &Workbench, p: AccountsParams) -> Reply<Page<AccountRow>> {
    let needle = p.text.unwrap_or_default().to_lowercase();
    let rows: Vec<AccountRow> = wb
        .accounts()
        .map_err(fail)?
        .iter()
        .filter(|a| !p.funds_only || a.holds_funds())
        .filter(|a| needle.is_empty() || a.service().to_lowercase().contains(&needle) || a.identifier().to_lowercase().contains(&needle))
        .map(AccountRow::of)
        .collect();
    Ok(Page::slice(rows, p.offset, Paging::LIST.limit(p.limit)))
}

fn leads(wb: &Workbench, p: LeadsParams) -> Reply<Page<LeadRow>> {
    Page::slice(wb.leads().map_err(fail)?, p.offset, Paging::LIST.limit(p.limit)).try_map(|l| LeadRow::of(wb, &l, p.resolve))
}

#[tool_router(router = insight_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Accounts on online services (exchanges, web wallets, faucets, mining pools, forums, mail...) merged \
        from e-mails, logins in URLs and forms, saved browser logins, cookies, mail settings and miner configs, with first \
        and last seen dates and the traces that name them. Fund-holding services first."
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
