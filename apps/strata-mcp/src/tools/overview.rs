//! What the case holds at a glance (disks, volumes, scan coverage, finding counts, jobs,
//! balances) and the job list.

use crate::StrataServer;
use crate::format::{Reply, btc, fail, unix_time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strata_workbench::{AccountQuery, EvidenceRecord, JobState, JobView, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct OverviewParams {
    /// Also report unreadable bytes per disk. This opens each disk image or drive (read-only),
    /// which can be slow and fails for a drive that is not attached. Default false.
    pub include_damage: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct JobsParams {
    /// Only jobs that are queued, running or interrupted. Default false (the whole history).
    pub unfinished_only: bool,
}

#[derive(Serialize)]
struct Overview {
    case: String,
    disks: Vec<Disk>,
    /// Distinct findings per category at or above `min_confidence`.
    findings: Findings,
    jobs: JobsSummary,
    balances: BalanceSummary,
    /// Accounts the owner used (see `accounts`; names only seen in data are not counted).
    accounts: usize,
    leads: usize,
}

#[derive(Serialize)]
struct Disk {
    id: u32,
    label: String,
    location: String,
    kind: String,
    size: u64,
    sector_size: u32,
    volumes: Vec<Volume>,
    scan: Option<ScanCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    damaged_bytes: Option<u64>,
    /// Why damage could not be read (the drive is not attached, say).
    #[serde(skip_serializing_if = "Option::is_none")]
    damage_error: Option<String>,
}

#[derive(Serialize)]
struct Volume {
    index: u32,
    start: u64,
    size: u64,
    filesystem: String,
    /// How the volume was found (partition table, boot-sector sweep, recovered...).
    origin: String,
    label: String,
}

#[derive(Serialize)]
struct ScanCoverage {
    scanned_bytes: u64,
    total_bytes: u64,
    completed: bool,
    percent: f64,
}

#[derive(Serialize)]
struct Findings {
    min_confidence: f32,
    per_category: BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct JobsSummary {
    total: usize,
    per_state: BTreeMap<String, usize>,
    /// Jobs that are queued, running or interrupted.
    unfinished: Vec<Job>,
}

#[derive(Serialize)]
struct BalanceSummary {
    addresses_checked: usize,
    /// Addresses with at least one transaction.
    used: usize,
    with_balance: usize,
    total_balance_sat: u64,
    total_balance_btc: String,
}

#[derive(Serialize)]
pub(crate) struct Job {
    id: u32,
    kind: String,
    disk: u32,
    title: String,
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    percent: f64,
    done_units: u64,
    total_units: u64,
    /// `Bytes` or `Items`.
    unit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    current: String,
    /// Where an interrupted job resumes.
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_from: Option<String>,
    created: Option<String>,
    started: Option<String>,
    finished: Option<String>,
    /// Pid of another live Strata process running the job (the app, usually).
    #[serde(skip_serializing_if = "Option::is_none")]
    running_in_pid: Option<u32>,
}

impl Job {
    fn of(v: &JobView) -> Self {
        let (state, detail) = match &v.state {
            JobState::Queued => ("Queued", ""),
            JobState::Running if v.is_paused() => ("Paused", ""),
            JobState::Running => ("Running", ""),
            JobState::Done(d) => ("Done", d.as_str()),
            JobState::Failed(d) => ("Failed", d.as_str()),
            JobState::Cancelled => ("Cancelled", ""),
            JobState::Interrupted => ("Interrupted", ""),
        };
        Self {
            id: v.id.0,
            kind: format!("{:?}", v.kind),
            disk: v.evidence.get(),
            title: v.title.clone(),
            state: state.to_string(),
            detail: detail.to_string(),
            percent: (f64::from(v.fraction()) * 1000.0).round() / 10.0,
            done_units: v.progress.scanned,
            total_units: v.progress.total,
            unit: format!("{:?}", v.unit),
            current: v.current.clone(),
            resume_from: v.checkpoint.as_ref().map(|c| c.note.clone()),
            created: unix_time(v.created_at),
            started: v.started_at.and_then(unix_time),
            finished: v.finished_at.and_then(unix_time),
            running_in_pid: v.foreign,
        }
    }

    fn unfinished(v: &JobView) -> bool {
        matches!(v.state, JobState::Queued | JobState::Running | JobState::Interrupted)
    }
}

fn disk(wb: &Workbench, e: &EvidenceRecord, include_damage: bool) -> Reply<Disk> {
    let damage = include_damage.then(|| wb.damaged_bytes(e.id));
    let scan = wb.scan_progress(e.id).map_err(fail)?.map(|(mark, total, completed)| ScanCoverage {
        scanned_bytes: mark,
        total_bytes: total,
        completed,
        percent: if total == 0 { 0.0 } else { (mark as f64 / total as f64 * 1000.0).round() / 10.0 },
    });
    let volumes = e
        .volumes
        .iter()
        .map(|v| Volume {
            index: v.index,
            start: v.range.start(),
            size: v.range.len(),
            filesystem: format!("{:?}", v.fs),
            origin: format!("{:?}", v.origin),
            label: v.label.clone(),
        })
        .collect();
    Ok(Disk {
        id: e.id.get(),
        label: e.info.label.clone(),
        location: e.info.location.clone(),
        kind: format!("{:?}", e.info.kind),
        size: e.info.len,
        sector_size: e.info.sector_size,
        volumes,
        scan,
        damaged_bytes: damage.as_ref().and_then(|d| d.as_ref().ok().copied()),
        damage_error: damage.and_then(|d| d.err().map(fail)),
    })
}

fn overview(wb: &Workbench, include_damage: bool) -> Reply<Overview> {
    let disks = wb.evidence().map_err(fail)?.iter().map(|e| disk(wb, e, include_damage)).collect::<Reply<_>>()?;
    let counts = wb.hit_counts(None, Workbench::NOISE_FLOOR).map_err(fail)?;
    let jobs = wb.jobs();
    let mut per_state = BTreeMap::new();
    for j in &jobs {
        *per_state.entry(Job::of(j).state).or_default() += 1;
    }
    let balances = wb.balances().map_err(fail)?;
    let total: u64 = balances.iter().map(|b| b.balance_sat()).sum();
    Ok(Overview {
        case: wb.name(),
        disks,
        findings: Findings {
            min_confidence: Workbench::NOISE_FLOOR,
            per_category: counts.into_iter().map(|(c, n)| (format!("{c:?}"), n)).collect(),
        },
        jobs: JobsSummary { total: jobs.len(), per_state, unfinished: jobs.iter().filter(|j| Job::unfinished(j)).map(Job::of).collect() },
        balances: BalanceSummary {
            addresses_checked: balances.len(),
            used: balances.iter().filter(|b| b.tx_count > 0).count(),
            with_balance: balances.iter().filter(|b| b.balance_sat() > 0).count(),
            total_balance_sat: total,
            total_balance_btc: btc(total),
        },
        accounts: wb.account_count(&AccountQuery::default()).map_err(fail)? as usize,
        leads: wb.leads().map_err(fail)?.len(),
    })
}

#[tool_router(router = overview_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Start here. Summary of the case: disks with size, kind, volumes (filesystem, origin) and how much of each \
        the deep scan covered; finding counts per category above the noise floor; job states; on-chain balance totals; \
        numbers of accounts and leads."
    )]
    pub async fn case_overview(&self, Parameters(p): Parameters<OverviewParams>) -> Reply<String> {
        self.query(move |wb| overview(wb, p.include_damage)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Analysis jobs of the case (index, deep scan, artefacts, carving, archives, balance check, searches, \
        recoveries) with state, progress percent, the item being worked on and where an interrupted job would resume. \
        Read-only: jobs cannot be started or changed from here."
    )]
    pub async fn jobs(&self, Parameters(p): Parameters<JobsParams>) -> Reply<String> {
        self.query(move |wb| Ok(wb.jobs().iter().filter(|j| !p.unfinished_only || Job::unfinished(j)).map(Job::of).collect::<Vec<_>>()))
            .await
    }
}
