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
use strata_engine::Scanner;
use strata_kernel::{EvidenceId, Result};

/// Facade over one open case plus its background jobs.
pub struct Workbench {
    pub(crate) case: Arc<Case>,
    pub(crate) queue: Arc<JobQueue>,
    pub(crate) policy: Mutex<CheckpointPolicy>,
    monitor: Monitor,
    indexes: crate::disk_index::IndexCache,
}

impl Workbench {
    /// Case setting: resume interrupted jobs when the case opens (on unless set to `0`).
    pub const AUTO_RESUME_KEY: &'static str = "auto_resume_jobs";
    /// Version of the detector and triage rules stored findings were made with. Bump it when
    /// a rule change alters what is a finding or adds a step older cases lack; older cases
    /// catch up on open (see [`Workbench::recheck_if_rules_changed`]).
    pub const RULES_VERSION: u32 = 3;
    /// Findings below this confidence are noise: hashes, rows of hex blocks, prose that happens
    /// to pass a checksum, matches inside system files. Lists hide them unless asked.
    pub const NOISE_FLOOR: f32 = 0.2;
    pub(crate) const RULES_KEY: &'static str = "rules_version";
    /// Case setting: the app's last screen, filters and selection (JSON chosen by the app).
    pub const UI_STATE_KEY: &'static str = "ui_state";

    /// Open (or create) a case and, if the case setting allows, resume jobs a crash or the
    /// last exit interrupted.
    pub fn open(case_dir: &Path) -> Result<Arc<Self>> {
        let wb = Self::open_idle(case_dir)?;
        if wb.auto_resume() {
            wb.resume_interrupted();
        }
        wb.recheck_if_rules_changed()?;
        Ok(wb)
    }

    /// Open without resuming anything (listing jobs, scripted single steps).
    pub fn open_idle(case_dir: &Path) -> Result<Arc<Self>> {
        let case = Arc::new(Case::open(case_dir)?);
        let queue = Arc::new(JobQueue::load(&case)?);
        let monitor = Monitor::start(Arc::downgrade(&queue));
        Ok(Arc::new(Self { case, queue, policy: Mutex::new(CheckpointPolicy::default()), monitor, indexes: Default::default() }))
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

    /// Disk overview grid with `cells` cells (with per-cell content once a disk index exists).
    pub fn sector_map(&self, id: EvidenceId, cells: usize) -> Result<crate::SectorMap> {
        let map = crate::SectorMap::build(&self.case, id, cells)?;
        Ok(map.with_index(self.index().load(id).as_deref()))
    }

    pub(crate) fn index(&self) -> crate::disk_index::IndexService<'_> {
        crate::disk_index::IndexService::new(&self.case, &self.indexes)
    }

    /// Summary of the disk index and the dominant content class of `cells` equal slices of
    /// the disk (`None` before any scan or import built one).
    pub fn disk_index(&self, id: EvidenceId, cells: usize) -> Option<crate::DiskIndexView> {
        self.index().view(id, cells)
    }

    /// Byte ranges worth searching according to the disk index (everything that is not
    /// known to be empty or unreadable); `None` without an index.
    pub fn interesting_ranges(&self, id: EvidenceId) -> Option<Vec<strata_kernel::ByteRange>> {
        self.index().interesting_ranges(id)
    }

    /// Import the R-Studio scan file next to the evidence image, if there is one: verified
    /// volumes join the case and the disk index is seeded. Also done by [`Self::add_evidence`].
    pub fn import_scn(&self, id: EvidenceId) -> Result<Option<crate::ScnImport>> {
        self.index().import_scn(id)
    }

    /// Bytes known to be unreadable or absent in one evidence item.
    pub fn damaged_bytes(&self, id: EvidenceId) -> Result<u64> {
        Ok(self.case.source(id)?.damage().iter().map(|r| r.len()).sum())
    }

    pub fn add_evidence(&self, location: &str) -> Result<EvidenceRecord> {
        let record = self.case.add_evidence(location)?;
        // A broken scan file must not stop the evidence from being added; our scan covers it.
        match self.import_scn(record.id) {
            Ok(Some(_)) => self.case.record(record.id),
            _ => Ok(record),
        }
    }

    pub fn evidence(&self) -> Result<Vec<EvidenceRecord>> {
        self.case.evidence()
    }

    pub fn hits(&self, q: &HitQuery) -> Result<Vec<StoredHit>> {
        self.case.hits(q)
    }

    /// Distinct findings per category at or above `min_confidence` (see [`Self::NOISE_FLOOR`]).
    pub fn hit_counts(&self, evidence: Option<EvidenceId>, min_confidence: f32) -> Result<Vec<(HitCategory, u64)>> {
        self.case.hit_counts(evidence, min_confidence)
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
    pub const SCAN_THREADS_KEY: &'static str = "scan_threads";

    /// Detector threads for the deep scan (case setting; default [`Scanner::DEFAULT_WORKERS`]).
    pub fn scan_threads(&self) -> usize {
        self.case
            .setting(Self::SCAN_THREADS_KEY)
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(Scanner::DEFAULT_WORKERS)
            .clamp(1, 64)
    }

    pub fn set_scan_threads(&self, threads: usize) -> Result<()> {
        self.case.set_setting(Self::SCAN_THREADS_KEY, &threads.clamp(1, 64).to_string())
    }

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
        // Re-detection only knows table and sweep volumes; add back R-Studio and deep-scan ones.
        let _ = self.import_scn(evidence);
        crate::explore::PartitionRecovery::new(&self.case).run(evidence)?;
        let n = self.case.reattribute(evidence)?;
        Ok((n, self.triage(evidence)?))
    }

    /// Fold repeated copies, then re-apply false-positive triage (both also part of the deep
    /// scan step).
    pub fn triage(&self, evidence: EvidenceId) -> Result<usize> {
        self.case.compact_repeats(evidence)?;
        crate::triage::Triage::new(&self.case).run(evidence)
    }
}
