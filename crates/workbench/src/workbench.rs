use crate::jobs::context::CheckpointPolicy;
use crate::jobs::queue::JobQueue;
use crate::jobs::{JobId, JobView, LogLine};
use crate::monitor::Monitor;
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
use strata_chain::{AddressBalance, EsploraBackend};
use strata_case::{Case, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};

/// Facade over one open case plus its background jobs.
pub struct Workbench {
    pub(crate) case: Arc<Case>,
    pub(crate) queue: Arc<JobQueue>,
    pub(crate) policy: Mutex<CheckpointPolicy>,
    monitor: Monitor,
}

impl Workbench {
    /// Case setting: resume interrupted jobs when the case opens (on unless set to `0`).
    pub const AUTO_RESUME_KEY: &'static str = "auto_resume_jobs";
    /// Case setting: the app's last screen, filters and selection (JSON chosen by the app).
    pub const UI_STATE_KEY: &'static str = "ui_state";

    /// Open (or create) a case and, if the case setting allows, resume jobs a crash or the
    /// last exit interrupted.
    pub fn open(case_dir: &Path) -> Result<Arc<Self>> {
        let wb = Self::open_idle(case_dir)?;
        if wb.auto_resume() {
            wb.resume_interrupted();
        }
        Ok(wb)
    }

    /// Open without resuming anything (listing jobs, scripted single steps).
    pub fn open_idle(case_dir: &Path) -> Result<Arc<Self>> {
        let case = Arc::new(Case::open(case_dir)?);
        let queue = Arc::new(JobQueue::load(&case)?);
        let monitor = Monitor::start(Arc::downgrade(&queue));
        Ok(Arc::new(Self { case, queue, policy: Mutex::new(CheckpointPolicy::default()), monitor }))
    }

    pub fn auto_resume(&self) -> bool {
        self.case.setting(Self::AUTO_RESUME_KEY).ok().flatten().is_none_or(|v| v != "0")
    }

    pub fn set_auto_resume(&self, on: bool) -> Result<()> {
        self.case.set_setting(Self::AUTO_RESUME_KEY, if on { "1" } else { "0" })
    }

    /// The app's saved view state, if any.
    pub fn ui_state(&self) -> Option<String> {
        self.case.setting(Self::UI_STATE_KEY).ok().flatten()
    }

    pub fn set_ui_state(&self, json: &str) -> Result<()> {
        self.case.set_setting(Self::UI_STATE_KEY, json)
    }

    /// Resource monitor of this process and its jobs.
    pub fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    pub fn case(&self) -> &Arc<Case> {
        &self.case
    }

    /// Case display name (folder stem).
    pub fn name(&self) -> String {
        self.case.name()
    }

    pub fn root(&self) -> &Path {
        self.case.root()
    }

    /// `(watermark, total, completed)` of the last stored scan of one evidence item.
    pub fn scan_progress(&self, id: EvidenceId) -> Result<Option<(u64, u64, bool)>> {
        self.case.scan_state(id)
    }

    pub fn events(&self, q: &strata_case::EventQuery) -> Result<Vec<(EvidenceId, strata_timeline::TimelineEvent)>> {
        self.case.events(q)
    }

    pub fn events_per_day(&self, evidence: Option<EvidenceId>) -> Result<Vec<(strata_kernel::Timestamp, u64, u64)>> {
        self.case.events_per_day(evidence)
    }

    pub fn host_facts(&self, evidence: Option<EvidenceId>) -> Result<Vec<strata_case::HostFact>> {
        self.case.facts(evidence)
    }

    /// Disk overview grid with `cells` cells.
    pub fn sector_map(&self, id: EvidenceId, cells: usize) -> Result<crate::SectorMap> {
        crate::SectorMap::build(&self.case, id, cells)
    }

    /// Bytes known to be unreadable or absent in one evidence item.
    pub fn damaged_bytes(&self, id: EvidenceId) -> Result<u64> {
        Ok(self.case.source(id)?.damage().iter().map(|r| r.len()).sum())
    }

    pub fn add_evidence(&self, location: &str) -> Result<EvidenceRecord> {
        self.case.add_evidence(location)
    }

    pub fn evidence(&self) -> Result<Vec<EvidenceRecord>> {
        self.case.evidence()
    }

    pub fn hits(&self, q: &HitQuery) -> Result<Vec<StoredHit>> {
        self.case.hits(q)
    }

    pub fn hit_counts(&self, evidence: Option<EvidenceId>) -> Result<Vec<(HitCategory, u64)>> {
        self.case.hit_counts(evidence)
    }

    pub fn shared_findings(&self) -> Result<Vec<SharedFinding>> {
        CorrelationService::new(&self.case).shared_findings(&[
            HitCategory::PrivateKey,
            HitCategory::ExtendedKey,
            HitCategory::Mnemonic,
            HitCategory::Wallet,
            HitCategory::Address,
            HitCategory::Identity,
            HitCategory::Url,
        ])
    }

    pub fn file_complements(&self) -> Result<Vec<FileComplement>> {
        CorrelationService::new(&self.case).file_complements()
    }

    /// Every job of the case (recent history included), oldest first.
    pub fn jobs(&self) -> Vec<JobView> {
        self.queue.all().iter().map(|j| j.view()).collect()
    }

    /// Recent log lines of one job, oldest first.
    pub fn job_log(&self, id: JobId) -> Vec<LogLine> {
        self.queue.get(id).map(|j| j.log_lines()).unwrap_or_default()
    }

    pub fn has_active_jobs(&self) -> bool {
        self.queue.has_active()
    }

    /// Passwords of the user's own archives, tried on encrypted ZIP members by the
    /// unpack step. Nothing is generated or brute-forced.
    pub fn set_archive_passwords(&self, passwords: &[String]) -> Result<()> {
        self.case.set_setting(crate::steps::PASSWORDS_KEY, &passwords.join("\n"))
    }

    pub fn archive_passwords(&self) -> Vec<String> {
        let stored = self.case.setting(crate::steps::PASSWORDS_KEY).ok().flatten().unwrap_or_default();
        stored.lines().filter(|l| !l.is_empty()).map(str::to_string).collect()
    }

    pub const CHAIN_ENDPOINT_KEY: &'static str = "chain_endpoint";

    /// Esplora endpoint used for balance checks (case setting, mempool.space by default).
    pub fn chain_endpoint(&self) -> String {
        self.case
            .setting(Self::CHAIN_ENDPOINT_KEY)
            .ok()
            .flatten()
            .unwrap_or_else(|| EsploraBackend::MEMPOOL_SPACE.to_string())
    }

    pub fn set_chain_endpoint(&self, url: &str) -> Result<()> {
        self.case.set_setting(Self::CHAIN_ENDPOINT_KEY, url)
    }

    /// Write a report (`md`, `html`, `csv`, `json`) and return its path.
    pub fn export_report(&self, format: &str, dir: &Path) -> Result<std::path::PathBuf> {
        let renderer = strata_report::renderer_for(format)
            .ok_or_else(|| strata_kernel::Error::Other(format!("unknown report format {format}")))?;
        let report = strata_report::CaseReport::gather(&self.case, 0.0)?;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}-report.{}", self.case.name(), renderer.extension()));
        std::fs::write(&path, renderer.render(&report))?;
        Ok(path)
    }

    pub fn balances(&self) -> Result<Vec<AddressBalance>> {
        self.case.balances()
    }

    /// Re-detect volumes, re-map stored hits to files, then re-run triage.
    pub fn reattribute(&self, evidence: EvidenceId) -> Result<(usize, usize)> {
        self.case.refresh_volumes(evidence)?;
        let n = self.case.reattribute(evidence)?;
        Ok((n, self.triage(evidence)?))
    }

    /// Re-apply false-positive triage (also part of the deep scan step).
    pub fn triage(&self, evidence: EvidenceId) -> Result<usize> {
        crate::triage::Triage::new(&self.case).run(evidence)
    }
}
