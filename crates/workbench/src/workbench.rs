use crate::catalog::DetectorCatalog;
use crate::jobs::{Job, JobId, JobKind, JobState, JobView};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
use strata_chain::{AddressBalance, ChainBackend, EsploraBackend};
use strata_case::{Case, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
use strata_engine::{ScanControl, Scanner};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};

/// Facade over one open case plus its background jobs.
pub struct Workbench {
    case: Arc<Case>,
    jobs: Mutex<Vec<Arc<Job>>>,
}

impl Workbench {
    pub fn open(case_dir: &Path) -> Result<Arc<Self>> {
        Ok(Arc::new(Self { case: Arc::new(Case::open(case_dir)?), jobs: Mutex::new(Vec::new()) }))
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

    pub fn jobs(&self) -> Vec<JobView> {
        self.jobs.lock().iter().map(|j| j.view()).collect()
    }

    pub fn cancel_job(&self, id: JobId) {
        if let Some(j) = self.jobs.lock().iter().find(|j| j.id == id) {
            j.cancel();
        }
    }

    pub fn has_active_jobs(&self) -> bool {
        self.jobs.lock().iter().any(|j| j.is_active())
    }

    /// Index files, then scan — the standard "analyse this disk" pipeline, on a background
    /// thread. Returns immediately.
    pub fn analyse(self: &Arc<Self>, evidence: EvidenceId) -> JobId {
        let index = self.enqueue(JobKind::IndexFiles, evidence);
        let scan = self.enqueue(JobKind::Scan, evidence);
        let this = self.clone();
        let scan_id = scan.id;
        std::thread::Builder::new()
            .name(format!("analyse-{evidence}"))
            .spawn(move || {
                this.run_job(&index);
                if index.control.is_cancelled() {
                    *scan.state.lock() = JobState::Cancelled;
                    return;
                }
                this.run_job(&scan);
                if !matches!(*scan.state.lock(), JobState::Done(_)) {
                    return;
                }
                // Follow-ups: each one is optional and runs only while nothing was cancelled.
                for kind in [JobKind::Artifacts, JobKind::ClassifyFiles, JobKind::Carve, JobKind::CheckBalances] {
                    let job = this.enqueue(kind, evidence);
                    this.run_job(&job);
                    if job.control.is_cancelled() {
                        break;
                    }
                }
            })
            .expect("spawn analysis thread");
        scan_id
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

    fn check_balances(&self, control: &ScanControl) -> Result<String> {
        let addresses = self.case.unchecked_addresses()?;
        let backend = EsploraBackend::new(&self.chain_endpoint());
        control.begin_items(addresses.len() as u64);
        let (mut used, mut failed) = (0, 0);
        for a in &addresses {
            if control.is_cancelled() {
                break;
            }
            match backend.balance(a) {
                Ok(b) => {
                    used += u32::from(b.ever_used());
                    self.case.store_balance(&b)?;
                }
                Err(_) => failed += 1,
            }
            control.item_done();
        }
        Ok(format!("{} addresses, {used} used on chain, {failed} lookups failed", addresses.len()))
    }

    /// Run one pipeline step in the foreground (CLI, re-running a step after an upgrade).
    pub fn run_step(&self, kind: JobKind, evidence: EvidenceId) -> JobView {
        let job = self.enqueue(kind, evidence);
        self.run_job(&job);
        job.view()
    }

    /// Re-map stored hits to files, then re-run triage.
    pub fn reattribute(&self, evidence: EvidenceId) -> Result<(usize, usize)> {
        let n = self.case.reattribute(evidence)?;
        Ok((n, self.triage(evidence)?))
    }

    /// Re-apply false-positive triage (also part of the deep scan step).
    pub fn triage(&self, evidence: EvidenceId) -> Result<usize> {
        crate::triage::Triage::new(&self.case).run(evidence)
    }

    fn enqueue(&self, kind: JobKind, evidence: EvidenceId) -> Arc<Job> {
        let mut jobs = self.jobs.lock();
        let title = match kind {
            JobKind::IndexFiles => format!("Index files {evidence}"),
            JobKind::Scan => format!("Deep scan {evidence}"),
            JobKind::ClassifyFiles => format!("Classify files {evidence}"),
            JobKind::Carve => format!("Carve free space {evidence}"),
            JobKind::Artifacts => format!("Artefacts and timeline {evidence}"),
            JobKind::CheckBalances => "Check balances".to_string(),
        };
        let job = Arc::new(Job {
            id: JobId(jobs.len() as u32 + 1),
            kind,
            evidence,
            title,
            control: Arc::new(ScanControl::default()),
            state: Mutex::new(JobState::Queued),
        });
        jobs.push(job.clone());
        job
    }

    fn run_job(&self, job: &Job) {
        *job.state.lock() = JobState::Running;
        let result = match job.kind {
            JobKind::IndexFiles => self.case.index_files(job.evidence).and_then(|n| {
                let wallets = crate::wallet_files::WalletFileAnalyzer::new(&self.case).run(job.evidence)?;
                Ok(format!("{n} entries, {wallets} wallet files"))
            }),
            JobKind::Scan => {
                let scanner = Scanner::new(DetectorCatalog::all());
                self.case.scan(job.evidence, &scanner, &job.control).and_then(|s| {
                    let downgraded = crate::triage::Triage::new(&self.case).run(job.evidence)?;
                    Ok(format!("{} hits in {:.0}s, {downgraded} inside system files", s.hits, s.elapsed_secs))
                })
            }
            JobKind::CheckBalances => self.check_balances(&job.control),
            JobKind::ClassifyFiles => crate::file_types::FileClassifier::new(&self.case)
                .run(job.evidence, &job.control)
                .map(|(n, s)| format!("{n} files, {s} suspicious renames")),
            JobKind::Artifacts => crate::artifacts_job::ArtifactsJob::new(&self.case)
                .run(job.evidence)
                .map(|(e, i, f)| format!("{e} events, {i} identities, {f} host facts")),
            JobKind::Carve => crate::carving::UnallocatedCarver::new(&self.case)
                .run(job.evidence, &job.control)
                .map(|(n, w)| format!("{n} files carved, {w} wallets")),
        };
        *job.state.lock() = match result {
            _ if job.control.is_cancelled() => JobState::Cancelled,
            Ok(msg) => JobState::Done(msg),
            Err(e) => JobState::Failed(e.to_string()),
        };
    }
}
