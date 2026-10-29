use crate::catalog::DetectorCatalog;
use crate::jobs::{Job, JobId, JobKind, JobState, JobView};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
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
                if !index.control.is_cancelled() {
                    this.run_job(&scan);
                } else {
                    *scan.state.lock() = JobState::Cancelled;
                }
            })
            .expect("spawn analysis thread");
        scan_id
    }

    fn enqueue(&self, kind: JobKind, evidence: EvidenceId) -> Arc<Job> {
        let mut jobs = self.jobs.lock();
        let title = match kind {
            JobKind::IndexFiles => format!("Index files {evidence}"),
            JobKind::Scan => format!("Deep scan {evidence}"),
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
            JobKind::IndexFiles => self.case.index_files(job.evidence).map(|n| format!("{n} entries")),
            JobKind::Scan => {
                let scanner = Scanner::new(DetectorCatalog::all());
                self.case
                    .scan(job.evidence, &scanner, &job.control)
                    .map(|s| format!("{} hits in {:.0}s", s.hits, s.elapsed_secs))
            }
        };
        *job.state.lock() = match result {
            _ if job.control.is_cancelled() => JobState::Cancelled,
            Ok(msg) => JobState::Done(msg),
            Err(e) => JobState::Failed(e.to_string()),
        };
    }
}
