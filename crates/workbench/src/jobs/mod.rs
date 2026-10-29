use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use strata_engine::{ScanControl, ScanSnapshot};
use strata_kernel::EvidenceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct JobId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum JobKind {
    /// Parse filesystems and store the file listing.
    IndexFiles,
    /// Browser history, registry, LNK, prefetch... into the timeline.
    Artifacts,
    /// Identify every file by content; flag renamed extensions.
    ClassifyFiles,
    /// Unpack archives (live, deleted, renamed, carved) recursively and analyse their members.
    Archives,
    /// Carve files from unallocated space and parse wallets found there.
    Carve,
    /// Single-pass detector scan of the whole evidence.
    Scan,
    /// Look up on-chain balances of every found or derived address.
    CheckBalances,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum JobState {
    Queued,
    Running,
    Done(String),
    Failed(String),
    Cancelled,
}

/// A background task with live progress.
pub struct Job {
    pub id: JobId,
    pub kind: JobKind,
    pub evidence: EvidenceId,
    pub title: String,
    pub(crate) control: Arc<ScanControl>,
    pub(crate) state: Mutex<JobState>,
}

/// Immutable snapshot for rendering.
#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: JobId,
    pub kind: JobKind,
    pub evidence: EvidenceId,
    pub title: String,
    pub state: JobState,
    pub progress: ScanSnapshot,
}

impl Job {
    pub fn view(&self) -> JobView {
        JobView {
            id: self.id,
            kind: self.kind,
            evidence: self.evidence,
            title: self.title.clone(),
            state: self.state.lock().clone(),
            progress: self.control.snapshot(),
        }
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub fn is_active(&self) -> bool {
        matches!(*self.state.lock(), JobState::Queued | JobState::Running)
    }
}

impl JobView {
    /// 0..=1 completion, using the contiguous watermark for scans.
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if p.total == 0 {
            return if matches!(self.state, JobState::Done(_)) { 1.0 } else { 0.0 };
        }
        (p.scanned as f64 / p.total as f64).clamp(0.0, 1.0) as f32
    }
}
