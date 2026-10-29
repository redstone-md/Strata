//! The open case as seen by the UI: the [`Workbench`] plus a cached snapshot that views render
//! from. Polls every 500 ms while background jobs run or the Tasks screen is open; idle
//! polling costs one atomic check. The snapshot is built on a background thread: on a large
//! case its queries take a few hundred milliseconds, which must never stall a frame.

use gpui::{Context, Task};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use strata_workbench::{
    AddressBalance, EvidenceId, EvidenceRecord, HitCategory, Period, JobId, JobKind, JobState, JobView, LogLine, MonitorView, Workbench,
};

const POLL: Duration = Duration::from_millis(500);
/// Counts and disks are rebuilt every this many polls while jobs run (3 s); job progress
/// and resource use every poll.
const FULL_EVERY: u32 = 6;
/// Finding counts are recounted every this many polls while jobs run (30 s): on a large case
/// counting distinct findings takes seconds.
const COUNT_EVERY: u32 = 60;

/// One disk as the overview shows it.
#[derive(Clone)]
pub struct DiskSummary {
    pub record: EvidenceRecord,
    /// 0..=1 of the disk covered by the detector scan.
    pub scanned: f32,
    pub scan_complete: bool,
    pub damaged: u64,
}

impl DiskSummary {
    pub fn id(&self) -> EvidenceId {
        self.record.id
    }
}

#[derive(Default, Clone)]
pub struct Snapshot {
    pub disks: Vec<DiskSummary>,
    pub counts: Vec<(HitCategory, u64)>,
    pub jobs: Vec<JobView>,
    pub total_hits: u64,
    /// Addresses seen on chain at least once, richest first.
    pub balances: Vec<AddressBalance>,
    /// Every address the chain lookup has checked, used or not.
    pub checked: Arc<Vec<AddressBalance>>,
}

impl Snapshot {
    pub fn count(&self, category: HitCategory) -> u64 {
        self.counts.iter().find(|(c, _)| *c == category).map_or(0, |(_, n)| *n)
    }

    /// What a job does and on which disk, by the disk's label.
    pub fn job_title(&self, job: &JobView) -> String {
        match job.kind {
            JobKind::CheckBalances => crate::format::job_name(job.kind).to_string(),
            // These carry their own titles: the query, the files and where they go.
            JobKind::Search | JobKind::Recover => job.title.clone(),
            kind => format!("{} {}", crate::format::job_name(kind), self.disk_label(job.evidence)),
        }
    }

    pub fn disk_label(&self, id: EvidenceId) -> String {
        self.disks.iter().find(|d| d.id() == id).map_or_else(|| id.to_string(), |d| d.record.info.label.clone())
    }

    /// Take fresh job states (in memory, cheap) and move the scan progress of each disk with them.
    fn set_jobs(&mut self, jobs: Vec<JobView>) {
        for disk in &mut self.disks {
            if let Some(job) = Self::running_scan(&jobs, disk.id()) {
                disk.scanned = job.fraction();
            }
        }
        self.jobs = jobs;
    }

    fn running_scan(jobs: &[JobView], disk: EvidenceId) -> Option<&JobView> {
        jobs.iter().rev().find(|j| j.evidence == disk && j.kind == JobKind::Scan && j.state == JobState::Running)
    }

    pub fn active_jobs(&self) -> impl Iterator<Item = &JobView> {
        self.jobs.iter().filter(|j| matches!(j.state, JobState::Queued | JobState::Running))
    }

    /// The job currently doing work, if any.
    pub fn running_job(&self) -> Option<&JobView> {
        self.jobs.iter().find(|j| j.state == JobState::Running && j.foreign.is_none())
    }
}

/// What opening a case is doing now; written by the opening thread, read by the splash.
#[derive(Default)]
pub struct OpenProgress {
    step: Mutex<&'static str>,
}

impl OpenProgress {
    pub fn set(&self, step: &'static str) {
        *self.step.lock().unwrap_or_else(|e| e.into_inner()) = step;
    }

    pub fn step(&self) -> &'static str {
        *self.step.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A case being opened in the background.
#[derive(Clone)]
pub struct Opening {
    pub name: String,
    pub progress: Arc<OpenProgress>,
    pub started: Instant,
}

impl Opening {
    pub fn new(dir: &Path) -> Self {
        let name = dir.file_stem().map_or_else(|| dir.display().to_string(), |s| s.to_string_lossy().into_owned());
        Self { name, progress: Arc::default(), started: Instant::now() }
    }
}

/// An opened case and its first snapshot, built off the UI thread.
pub struct Opened {
    workbench: Arc<Workbench>,
    snapshot: Snapshot,
    error: Option<String>,
}

pub struct Session {
    workbench: Arc<Workbench>,
    snapshot: Snapshot,
    error: Option<String>,
    /// Show the raw details JSON under each finding (Settings, off by default).
    show_raw: bool,
    /// Bumped whenever the case is switched, so views can rebuild their state.
    generation: u64,
    was_active: bool,
    /// Resource history, refreshed while the Tasks screen is open or jobs run.
    monitor: MonitorView,
    tasks_visible: bool,
    /// A snapshot is being built; `stale` asks for another one when it lands.
    loading: bool,
    stale: bool,
    /// Finding counts are being recounted.
    counting: bool,
    ticks: u32,
    /// Set while another case is being opened (Settings).
    opening: Option<Opening>,
    /// The period of interest every list is narrowed to (stored in the case).
    period: Period,
    _poll: Task<()>,
}

impl Session {
    /// Open a case and read its first snapshot. Blocking: run on a background thread. A case
    /// that cannot be opened is replaced by a temporary one, with the error kept for the UI.
    pub fn open(case_dir: &Path, progress: &OpenProgress) -> Opened {
        match Self::try_open(case_dir, progress) {
            Ok((workbench, snapshot)) => Opened { workbench, snapshot, error: None },
            Err(e) => {
                let workbench = Self::fallback_workbench();
                let snapshot = Self::load(&workbench);
                Opened { workbench, snapshot, error: Some(format!(
                    "Cannot open case {}: {e}. A temporary case is open instead; pick another case in Settings.",
                    case_dir.display()
                )) }
            }
        }
    }

    fn try_open(case_dir: &Path, progress: &OpenProgress) -> strata_workbench::Result<(Arc<Workbench>, Snapshot)> {
        progress.set("Reading the case database");
        let workbench = Workbench::open_idle(case_dir)?;
        progress.set("Loading disks and findings");
        let snapshot = Self::load(&workbench);
        if workbench.auto_resume() {
            progress.set("Resuming interrupted jobs");
            workbench.resume_interrupted();
        }
        workbench.recheck_if_rules_changed()?;
        Ok((workbench, snapshot))
    }

    pub fn new(opened: Opened, cx: &mut Context<Self>) -> Self {
        let Opened { workbench, snapshot, error } = opened;
        let period = workbench.period();
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(POLL).await;
                if this.update(cx, |s, cx| s.tick(cx)).is_err() {
                    break;
                }
            }
        });
        Self {
            workbench,
            snapshot,
            error,
            show_raw: false,
            generation: 0,
            was_active: false,
            monitor: MonitorView::default(),
            tasks_visible: false,
            loading: false,
            stale: false,
            counting: false,
            ticks: 0,
            opening: None,
            period,
            _poll: poll,
        }
    }

    /// In-temp case used only if the requested case cannot be opened, so the UI still runs.
    fn fallback_workbench() -> Arc<Workbench> {
        let dir = std::env::temp_dir().join("strata-fallback.strata");
        Workbench::open_idle(&dir).expect("temporary fallback case")
    }

    pub fn workbench(&self) -> &Arc<Workbench> {
        &self.workbench
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn case_name(&self) -> String {
        self.workbench.name()
    }

    pub fn case_root(&self) -> PathBuf {
        self.workbench.root().to_path_buf()
    }

    pub fn show_raw(&self) -> bool {
        self.show_raw
    }

    pub fn set_show_raw(&mut self, show: bool, cx: &mut Context<Self>) {
        self.show_raw = show;
        cx.notify();
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn monitor(&self) -> &MonitorView {
        &self.monitor
    }

    pub fn job_log(&self, id: JobId) -> Vec<LogLine> {
        self.workbench.job_log(id)
    }

    /// The Tasks screen opened or closed: sample resources only while someone looks.
    pub fn set_tasks_visible(&mut self, visible: bool, cx: &mut Context<Self>) {
        if visible == self.tasks_visible {
            return;
        }
        self.tasks_visible = visible;
        if visible {
            self.workbench.monitor().watch();
        } else {
            self.workbench.monitor().unwatch();
        }
        self.refresh(cx);
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        self.ticks = self.ticks.wrapping_add(1);
        let active = self.workbench.has_active_jobs();
        let settled = self.was_active && !active;
        if settled || (active && self.ticks % COUNT_EVERY == 0) {
            self.recount(cx);
        }
        if settled || (active && !self.loading && self.ticks % FULL_EVERY == 0) {
            self.refresh(cx);
        } else if active || self.tasks_visible {
            self.monitor = self.workbench.monitor().view();
            self.snapshot.set_jobs(self.workbench.jobs());
            cx.notify();
        }
        self.was_active = active;
    }

    /// Rebuild the snapshot in the background. Job states are in memory and update at once,
    /// so buttons react immediately; counts and disks follow when the queries finish.
    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.snapshot.set_jobs(self.workbench.jobs());
        if self.tasks_visible || self.was_active {
            self.monitor = self.workbench.monitor().view();
        }
        cx.notify();
        if self.loading {
            self.stale = true;
            return;
        }
        self.loading = true;
        let wb = self.workbench.clone();
        let generation = self.generation;
        cx.spawn(async move |this, cx| {
            let snapshot = cx.background_executor().spawn(async move { Self::load(&wb) }).await;
            let _ = this.update(cx, |s, cx| {
                s.loading = false;
                if s.generation == generation {
                    s.snapshot = Snapshot { counts: std::mem::take(&mut s.snapshot.counts), total_hits: s.snapshot.total_hits, ..snapshot };
                    cx.notify();
                }
                if std::mem::take(&mut s.stale) || s.generation != generation {
                    s.refresh(cx);
                }
            });
        })
        .detach();
    }

    /// Recount findings above the noise floor in the background (skipped while a count runs).
    pub fn recount(&mut self, cx: &mut Context<Self>) {
        if self.counting {
            return;
        }
        self.counting = true;
        let wb = self.workbench.clone();
        let generation = self.generation;
        cx.spawn(async move |this, cx| {
            let counts = cx.background_executor().spawn(async move { wb.hit_counts(None, Workbench::NOISE_FLOOR) }).await;
            let _ = this.update(cx, |s, cx| {
                s.counting = false;
                if s.generation != generation {
                    return s.recount(cx);
                }
                if let Ok(counts) = counts {
                    s.snapshot.total_hits = counts.iter().map(|(_, n)| n).sum();
                    s.snapshot.counts = counts;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn load(wb: &Workbench) -> Snapshot {
        let jobs = wb.jobs();
        let disks = wb
            .evidence()
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                let running = Snapshot::running_scan(&jobs, record.id);
                let stored = wb.scan_progress(record.id).ok().flatten();
                let (scanned, scan_complete) = match (running, stored) {
                    (Some(job), _) => (job.fraction(), false),
                    (None, Some((mark, total, done))) => {
                        (if done { 1.0 } else if total == 0 { 0.0 } else { mark as f32 / total as f32 }, done)
                    }
                    (None, None) => (0.0, false),
                };
                let damaged = wb.damaged_bytes(record.id).unwrap_or(0);
                DiskSummary { record, scanned, scan_complete, damaged }
            })
            .collect();
        let checked = wb.balances().unwrap_or_default();
        let mut balances: Vec<_> = checked.iter().filter(|b| b.ever_used()).cloned().collect();
        balances.sort_by(|a, b| b.balance_sat().cmp(&a.balance_sat()).then(b.tx_count.cmp(&a.tx_count)));
        Snapshot { disks, jobs, balances, checked: Arc::new(checked), ..Snapshot::default() }
    }

    /// Add a disk; `deep` also probes old CHS cylinder boundaries for deleted partitions.
    pub fn add_evidence(&mut self, location: &str, deep: bool, cx: &mut Context<Self>) -> Result<(), String> {
        let location = location.trim().trim_matches('"');
        if location.is_empty() {
            return Err(r"Enter the path of a disk image, or \\.\PhysicalDrive1 for a drive.".into());
        }
        let added = if deep { self.workbench.add_evidence_deep(location) } else { self.workbench.add_evidence(location) };
        added.map_err(|e| e.to_string())?;
        self.refresh(cx);
        Ok(())
    }

    pub fn analyse(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        if let Err(e) = self.workbench.analyse(id) {
            self.error = Some(format!("Cannot start the analysis: {e}"));
        }
        self.was_active = true;
        self.refresh(cx);
    }

    /// A job was started elsewhere (search, recovery): poll until it settles, even if it
    /// finishes before the next tick.
    pub fn watch_jobs(&mut self, cx: &mut Context<Self>) {
        self.was_active = true;
        self.refresh(cx);
    }

    pub fn cancel(&mut self, job: JobId, cx: &mut Context<Self>) {
        self.workbench.cancel_job(job);
        self.refresh(cx);
    }

    pub fn pause(&mut self, job: JobId, cx: &mut Context<Self>) {
        self.workbench.pause_job(job);
        self.refresh(cx);
    }

    pub fn resume(&mut self, job: JobId, cx: &mut Context<Self>) {
        self.workbench.resume_job(job);
        self.refresh(cx);
    }

    /// Cancel every queued or running job of one disk.
    pub fn cancel_disk(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        for job in self.snapshot.active_jobs().filter(|j| j.evidence == id) {
            self.workbench.cancel_job(job.id);
        }
        self.refresh(cx);
    }

    pub fn period(&self) -> Period {
        self.period
    }

    /// Narrow every list to `period` and remember it in the case.
    pub fn set_period(&mut self, period: Period, cx: &mut Context<Self>) {
        if let Err(e) = self.workbench.set_period(period) {
            self.error = Some(format!("Cannot save the period: {e}"));
        }
        self.period = period;
        cx.notify();
    }

    /// The case being opened instead of this one, if any.
    pub fn opening(&self) -> Option<&Opening> {
        self.opening.as_ref()
    }

    /// Open another case on a background thread; the current one stays usable until it is
    /// ready. Resolves when the switch is done or has failed.
    pub fn switch_case(&mut self, dir: PathBuf, cx: &mut Context<Self>) -> Task<Result<(), String>> {
        let opening = Opening::new(&dir);
        let progress = opening.progress.clone();
        self.opening = Some(opening);
        cx.notify();
        cx.spawn(async move |this, cx| {
            let opened = cx.background_executor().spawn(async move { Self::try_open(&dir, &progress) }).await;
            this.update(cx, |s, cx| {
                s.opening = None;
                let result = opened.map(|(wb, snapshot)| {
                    if s.tasks_visible {
                        s.workbench.monitor().unwatch();
                        wb.monitor().watch();
                    }
                    s.period = wb.period();
                    s.workbench = wb;
                    s.snapshot = snapshot;
                    s.generation += 1;
                    s.error = None;
                });
                if result.is_ok() {
                    s.recount(cx);
                }
                cx.notify();
                result.map_err(|e| e.to_string())
            })
            .unwrap_or_else(|_| Err("the window was closed".into()))
        })
    }
}
