//! The open case as seen by the UI: the [`Workbench`] plus a cached snapshot that views render
//! from. Polls every 500 ms while background jobs run; idle polling costs one atomic check.

use gpui::{Context, Task};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use strata_workbench::{AddressBalance, EvidenceId, EvidenceRecord, HitCategory, JobId, JobState, JobView, Workbench};

const POLL: Duration = Duration::from_millis(500);

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
}

impl Snapshot {
    pub fn count(&self, category: HitCategory) -> u64 {
        self.counts.iter().find(|(c, _)| *c == category).map_or(0, |(_, n)| *n)
    }

    pub fn disk_label(&self, id: EvidenceId) -> String {
        self.disks.iter().find(|d| d.id() == id).map_or_else(|| id.to_string(), |d| d.record.info.label.clone())
    }

    pub fn active_jobs(&self) -> impl Iterator<Item = &JobView> {
        self.jobs.iter().filter(|j| matches!(j.state, JobState::Queued | JobState::Running))
    }

    /// The job currently doing work, if any.
    pub fn running_job(&self) -> Option<&JobView> {
        self.jobs.iter().find(|j| j.state == JobState::Running)
    }
}

pub struct Session {
    workbench: Arc<Workbench>,
    snapshot: Snapshot,
    error: Option<String>,
    /// Bumped whenever the case is switched, so views can rebuild their state.
    generation: u64,
    was_active: bool,
    _poll: Task<()>,
}

impl Session {
    pub fn new(case_dir: &Path, cx: &mut Context<Self>) -> Self {
        let (workbench, error) = match Workbench::open(case_dir) {
            Ok(wb) => (wb, None),
            Err(e) => (Self::fallback_workbench(), Some(format!("Cannot open case {}: {e}", case_dir.display()))),
        };
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(POLL).await;
                if this.update(cx, |s, cx| s.tick(cx)).is_err() {
                    break;
                }
            }
        });
        let mut session = Self { workbench, snapshot: Snapshot::default(), error, generation: 0, was_active: false, _poll: poll };
        session.reload();
        session
    }

    /// In-temp case used only if the requested case cannot be opened, so the UI still runs.
    fn fallback_workbench() -> Arc<Workbench> {
        let dir = std::env::temp_dir().join("strata-fallback.strata");
        Workbench::open(&dir).expect("temporary fallback case")
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

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn tick(&mut self, cx: &mut Context<Self>) {
        let active = self.workbench.has_active_jobs();
        if active || self.was_active {
            self.refresh(cx);
        }
        self.was_active = active;
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.reload();
        cx.notify();
    }

    fn reload(&mut self) {
        let wb = &self.workbench;
        let jobs = wb.jobs();
        let disks = wb
            .evidence()
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                let running = jobs.iter().rev().find(|j| {
                    j.evidence == record.id && j.kind == strata_workbench::JobKind::Scan && j.state == JobState::Running
                });
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
        let counts = wb.hit_counts(None).unwrap_or_default();
        let total_hits = counts.iter().map(|(_, n)| n).sum();
        let mut balances: Vec<_> = wb.balances().unwrap_or_default().into_iter().filter(|b| b.ever_used()).collect();
        balances.sort_by(|a, b| b.balance_sat().cmp(&a.balance_sat()).then(b.tx_count.cmp(&a.tx_count)));
        self.snapshot = Snapshot { disks, counts, jobs, total_hits, balances };
    }

    pub fn add_evidence(&mut self, location: &str, cx: &mut Context<Self>) -> Result<(), String> {
        let location = location.trim().trim_matches('"');
        if location.is_empty() {
            return Err(r"Enter the path of a disk image, or \\.\PhysicalDrive1 for a drive.".into());
        }
        self.workbench.add_evidence(location).map_err(|e| e.to_string())?;
        self.refresh(cx);
        Ok(())
    }

    pub fn analyse(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        self.workbench.analyse(id);
        self.was_active = true;
        self.refresh(cx);
    }

    pub fn cancel(&mut self, job: JobId, cx: &mut Context<Self>) {
        self.workbench.cancel_job(job);
        self.refresh(cx);
    }

    /// Cancel every queued or running job of one disk.
    pub fn cancel_disk(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        for job in self.snapshot.active_jobs().filter(|j| j.evidence == id) {
            self.workbench.cancel_job(job.id);
        }
        self.refresh(cx);
    }

    pub fn switch_case(&mut self, dir: &Path, cx: &mut Context<Self>) -> Result<(), String> {
        let wb = Workbench::open(dir).map_err(|e| e.to_string())?;
        self.workbench = wb;
        self.generation += 1;
        self.error = None;
        self.refresh(cx);
        Ok(())
    }
}
