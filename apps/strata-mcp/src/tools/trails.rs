//! Wallet trails: for every trace that a wallet-relevant file existed, where it went (live,
//! moved, deleted, archived, mailed, carved, not found) and the chain of evidence behind it.

use crate::StrataServer;
use crate::format::{Bound, Page, Paging, Reply, date_param, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{Period, Trail, TrailFate, TrailLink, TrailStep, Workbench};

/// Fate filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FateFilter {
    Live,
    Moved,
    Deleted,
    Archive,
    Mail,
    Carved,
    NotFound,
}

impl FateFilter {
    fn matches(self, fate: TrailFate) -> bool {
        match self {
            Self::Live => fate == TrailFate::Live,
            Self::Moved => matches!(fate, TrailFate::Moved { .. }),
            Self::Deleted => matches!(fate, TrailFate::Deleted { .. }),
            Self::Archive => fate == TrailFate::InArchive,
            Self::Mail => fate == TrailFate::InMail,
            Self::Carved => fate == TrailFate::Carved,
            Self::NotFound => fate == TrailFate::NotFound,
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct WalletTrailsParams {
    /// Only trails with dates from here on: YYYY, YYYY-MM, YYYY-MM-DD (UTC). Undated trails stay.
    pub from: Option<String>,
    /// Only trails with dates up to the end of this period.
    pub to: Option<String>,
    /// Only this fate.
    pub fate: Option<FateFilter>,
    /// Part of the file name or path (any case).
    pub text: Option<String>,
    /// Trails per page, default 50, at most 500, best first.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
struct StepRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    at: Option<String>,
    kind: &'static str,
    text: String,
    disk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_id: Option<i64>,
    /// File-table path (for archive members, the archive).
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mail_id: Option<i64>,
}

impl StepRow {
    fn of(s: &TrailStep) -> Self {
        let mut row = Self {
            at: s.at.map(time),
            kind: s.kind.label(),
            text: s.text.clone(),
            disk: s.evidence.get(),
            event_id: None,
            finding_id: None,
            file: None,
            volume: None,
            mail_id: None,
        };
        match &s.link {
            TrailLink::Event(id) => row.event_id = Some(*id),
            TrailLink::Hit { id, .. } => row.finding_id = Some(*id),
            TrailLink::File { path, volume, .. } => (row.file, row.volume) = (Some(path.clone()), *volume),
            TrailLink::Message { id, .. } => row.mail_id = Some(*id),
        }
        row
    }
}

#[derive(Serialize)]
struct TrailRow {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    /// The path the traces name, as first written.
    origin: String,
    fate: &'static str,
    /// 0..1, how sure the fate is.
    confidence: f32,
    /// 0..100, comparable with lead scores.
    score: f32,
    /// Facts and the conclusion, one sentence each.
    explanation: Vec<String>,
    /// Where to look next, for files not found or not verified.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window: Option<[String; 2]>,
    disks: Vec<u32>,
    /// The chain of evidence, oldest first, undated last.
    steps: Vec<StepRow>,
}

impl TrailRow {
    fn of(t: &Trail) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            kind: t.kind.map(|k| k.label()),
            origin: t.origin.clone(),
            fate: t.verdict.fate.label(),
            confidence: (t.verdict.confidence * 100.0).round() / 100.0,
            score: t.score.round(),
            explanation: t.verdict.explanation.clone(),
            hints: t.hints.clone(),
            window: t.window.map(|(a, b)| [time(a), time(b)]),
            disks: t.evidence.iter().map(|d| d.get()).collect(),
            steps: t.steps.iter().map(StepRow::of).collect(),
        }
    }
}

fn wallet_trails(wb: &Workbench, p: WalletTrailsParams) -> Reply<Page<TrailRow>> {
    let period = Period { from: date_param(p.from.as_deref(), Bound::Start)?, to: date_param(p.to.as_deref(), Bound::End)? };
    let needle = p.text.unwrap_or_default().to_lowercase();
    let rows: Vec<TrailRow> = wb
        .wallet_trails(period)
        .map_err(fail)?
        .iter()
        .filter(|t| p.fate.is_none_or(|f| f.matches(t.verdict.fate)))
        .filter(|t| needle.is_empty() || t.name.to_lowercase().contains(&needle) || t.origin.to_lowercase().contains(&needle))
        .map(TrailRow::of)
        .collect();
    Ok(Page::slice(rows, p.offset, Paging::LIST.limit(p.limit)))
}

#[tool_router(router = trail_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Wallet trails: for every trace that a wallet-relevant file existed (wallet.dat, Electrum/MultiBit/Armory \
        wallets, keystores, files named like key or seed backups; shortcuts, recent documents, Prefetch, downloads, Recycle Bin, \
        file entries, wallet findings, archive members, mail attachments), where it went across all disks: live, moved or \
        copied, deleted (recoverable or not), only in an archive, only in mail, carved from free space, or not found. Each \
        trail has a verdict with confidence and plain sentences, the dated chain of evidence with event, finding, file and \
        mail ids, and hints where to look when the file was not found. Built on request (a few seconds on a large case)."
    )]
    pub async fn wallet_trails(&self, Parameters(p): Parameters<WalletTrailsParams>) -> Reply<String> {
        self.query(move |wb| wallet_trails(wb, p)).await
    }
}
