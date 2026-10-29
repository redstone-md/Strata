//! Background jobs: what they are ([`Job`], [`JobKind`], [`JobState`]), what the UI sees of
//! them ([`JobView`]), how they persist ([`queue`]) and run ([`runner`]), and the checkpoint
//! contract every step follows ([`context`]).

pub(crate) mod context;
mod log;
pub(crate) mod queue;
pub(crate) mod runner;
mod view;

pub use log::LogLine;
pub use view::{CheckpointInfo, JobView, ProgressUnit, eta};

use crate::monitor::ThreadSet;
use log::JobLog;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use strata_engine::ScanControl;
use strata_kernel::EvidenceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JobId(pub u32);

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl JobKind {
    /// The "analyse this disk" pipeline, in order.
    pub const PIPELINE: [JobKind; 7] = [
        Self::IndexFiles,
        Self::Scan,
        Self::Artifacts,
        Self::ClassifyFiles,
        Self::Carve,
        Self::Archives,
        Self::CheckBalances,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::IndexFiles => "IndexFiles",
            Self::Artifacts => "Artifacts",
            Self::ClassifyFiles => "ClassifyFiles",
            Self::Archives => "Archives",
            Self::Carve => "Carve",
            Self::Scan => "Scan",
            Self::CheckBalances => "CheckBalances",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::PIPELINE.into_iter().find(|k| k.name().eq_ignore_ascii_case(name))
    }

    /// What progress counts: bytes of the evidence or items (files, archives, addresses).
    pub fn unit(self) -> ProgressUnit {
        match self {
            Self::Scan | Self::Carve => ProgressUnit::Bytes,
            _ => ProgressUnit::Items,
        }
    }

    fn title(self, evidence: EvidenceId) -> String {
        match self {
            Self::IndexFiles => format!("Index files {evidence}"),
            Self::Scan => format!("Deep scan {evidence}"),
            Self::ClassifyFiles => format!("Classify files {evidence}"),
            Self::Archives => format!("Unpack archives {evidence}"),
            Self::Carve => format!("Carve free space {evidence}"),
            Self::Artifacts => format!("Artefacts and timeline {evidence}"),
            Self::CheckBalances => "Check balances".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum JobState {
    Queued,
    Running,
    Done(String),
    Failed(String),
    Cancelled,
    /// Stopped by a crash or by closing the app; resumes from its checkpoint.
    Interrupted,
}

impl JobState {
    /// `(state, detail)` as stored in the case.
    pub(crate) fn to_record(&self) -> (&'static str, &str) {
        match self {
            Self::Queued => ("Queued", ""),
            Self::Running => ("Running", ""),
            Self::Done(s) => ("Done", s),
            Self::Failed(s) => ("Failed", s),
            Self::Cancelled => ("Cancelled", ""),
            Self::Interrupted => ("Interrupted", ""),
        }
    }

    pub(crate) fn from_record(state: &str, detail: &str) -> Self {
        match state {
            "Queued" => Self::Queued,
            "Running" => Self::Running,
            "Done" => Self::Done(detail.to_string()),
            "Failed" => Self::Failed(detail.to_string()),
            "Cancelled" => Self::Cancelled,
            _ => Self::Interrupted,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

/// Why a job's control was cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum StopReason {
    None = 0,
    /// The user cancelled it: it ends as cancelled.
    Cancel = 1,
    /// The app is closing: it ends as interrupted and resumes on the next start.
    Shutdown = 2,
}

/// Last saved resume point of a job.
#[derive(Debug, Clone, Default)]
pub(crate) struct Checkpoint {
    /// `{"note": "...", "cursor": {...}}` as stored.
    pub json: Option<serde_json::Value>,
    /// Unix seconds of the save.
    pub saved_at: Option<i64>,
}

/// Unix seconds.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct JobTimes {
    pub created: i64,
    pub started: Option<i64>,
    pub finished: Option<i64>,
}

/// A background task with live progress.
pub struct Job {
    pub id: JobId,
    pub kind: JobKind,
    pub evidence: EvidenceId,
    pub title: String,
    pub(crate) pipeline: Option<JobId>,
    pub(crate) control: Arc<ScanControl>,
    pub(crate) state: Mutex<JobState>,
    pub(crate) checkpoint: Mutex<Checkpoint>,
    pub(crate) times: Mutex<JobTimes>,
    pub(crate) log: JobLog,
    pub(crate) threads: Arc<ThreadSet>,
    /// Pid of another live process that owns the job (shown, never run or resumed here).
    pub(crate) foreign: Option<u32>,
    stop: AtomicU8,
}

impl Job {
    pub(crate) fn new(id: JobId, kind: JobKind, evidence: EvidenceId, pipeline: Option<JobId>, state: JobState) -> Self {
        let control = Arc::new(ScanControl::default());
        let threads = Arc::new(ThreadSet::default());
        let set = threads.clone();
        control.set_thread_hook(Arc::new(move || set.register_current()));
        Self {
            id,
            kind,
            evidence,
            title: kind.title(evidence),
            pipeline,
            control,
            state: Mutex::new(state),
            checkpoint: Mutex::default(),
            times: Mutex::default(),
            log: JobLog::default(),
            threads,
            foreign: None,
            stop: AtomicU8::new(StopReason::None as u8),
        }
    }

    pub fn view(&self) -> JobView {
        JobView::of(self)
    }

    pub fn cancel(&self) {
        self.stop(StopReason::Cancel);
    }

    pub(crate) fn stop(&self, reason: StopReason) {
        let _ = self.stop.compare_exchange(StopReason::None as u8, reason as u8, Ordering::SeqCst, Ordering::SeqCst);
        self.control.cancel();
    }

    pub(crate) fn stop_reason(&self) -> StopReason {
        match self.stop.load(Ordering::SeqCst) {
            1 => StopReason::Cancel,
            2 => StopReason::Shutdown,
            _ => StopReason::None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.foreign.is_none() && self.state.lock().is_active()
    }

    /// Recent human-readable log lines, oldest first.
    pub fn log_lines(&self) -> Vec<LogLine> {
        self.log.lines()
    }
}
