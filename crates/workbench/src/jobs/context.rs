//! The one checkpoint contract every step follows.
//!
//! A step gets a [`StepContext`]. It reads its resume point with [`StepContext::cursor`],
//! works in units, calls [`StepContext::should_stop`] between units (this also blocks while
//! paused) and [`StepContext::tick`] after each, and when a checkpoint is due (or it stops)
//! calls [`StepContext::commit`] with its new cursor and the results of the batch. The results
//! and the cursor commit in one transaction, so after a crash a resumed step starts exactly
//! where the stored results end: nothing is duplicated and nothing is lost.

use super::{Job, JobKind};
use parking_lot::Mutex;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use strata_case::{Case, CaseWriter};
use strata_engine::ScanControl;
use strata_kernel::{ByteRange, Error, EvidenceId, Result};
use strata_source::{BlockSource, SourceInfo};

/// A step's resume point.
pub(crate) trait Cursor: Serialize + DeserializeOwned + Default {
    /// What a resumed run continues from, in words.
    fn note(&self) -> String;
}

/// When steps save a checkpoint: after `every` of work or `every_items` units, whichever
/// comes first, and always when they stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    pub every: Duration,
    pub every_items: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self { every: Duration::from_secs(2), every_items: 4096 }
    }
}

/// Fault injection for crash tests: after a number of checkpoint commits of one kind the
/// process "dies" — that commit and every later write of job state is dropped.
#[derive(Default)]
pub(crate) struct Faults {
    plan: Mutex<Option<(JobKind, u32)>>,
    commits: AtomicU32,
    dead: AtomicBool,
}

impl Faults {
    pub fn crash_after(&self, kind: JobKind, commits: u32) {
        *self.plan.lock() = Some((kind, commits));
        self.commits.store(0, Ordering::SeqCst);
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn before_commit(&self, kind: JobKind) -> Result<()> {
        if !self.is_dead()
            && let Some((k, n)) = *self.plan.lock()
            && k == kind
            && self.commits.fetch_add(1, Ordering::SeqCst) >= n
        {
            self.dead.store(true, Ordering::SeqCst);
        }
        if self.is_dead() { Err(Error::Other("simulated crash".into())) } else { Ok(()) }
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub(crate) struct StepContext<'a> {
    case: &'a Case,
    job: &'a Job,
    policy: CheckpointPolicy,
    faults: &'a Faults,
    last_commit: Mutex<Instant>,
    pending: AtomicU64,
}

impl<'a> StepContext<'a> {
    pub fn new(case: &'a Case, job: &'a Job, policy: CheckpointPolicy, faults: &'a Faults) -> Self {
        Self { case, job, policy, faults, last_commit: Mutex::new(Instant::now()), pending: AtomicU64::new(0) }
    }

    pub fn case(&self) -> &'a Case {
        self.case
    }

    pub fn evidence(&self) -> EvidenceId {
        self.job.evidence
    }

    pub fn control(&self) -> &'a ScanControl {
        &self.job.control
    }

    pub fn policy(&self) -> CheckpointPolicy {
        self.policy
    }

    /// The saved resume point, `None` on a fresh start.
    pub fn cursor<C: Cursor>(&self) -> Option<C> {
        let saved = self.job.checkpoint.lock().json.clone()?;
        serde_json::from_value(saved.get("cursor")?.clone()).ok()
    }

    /// Between units of work: blocks while paused, true once the step must stop.
    pub fn should_stop(&self) -> bool {
        self.job.control.should_stop()
    }

    /// What is being worked on, in words.
    pub fn current(&self, item: &str) {
        self.job.control.set_current(item);
    }

    pub fn log(&self, text: impl Into<String>) {
        self.job.log.push(text);
    }

    /// Count `units` of finished work; true when a checkpoint is due.
    pub fn tick(&self, units: u64) -> bool {
        let pending = self.pending.fetch_add(units, Ordering::Relaxed) + units;
        pending >= self.policy.every_items || self.last_commit.lock().elapsed() >= self.policy.every
    }

    /// Store a batch of results and the new cursor in one transaction.
    pub fn commit<C: Cursor, T>(&self, cursor: &C, store: impl FnOnce(&CaseWriter<'_>) -> Result<T>) -> Result<T> {
        let result = self.case.write(|w| {
            let out = store(w)?;
            self.checkpoint_in(w, cursor)?;
            Ok(out)
        });
        if result.is_err() {
            self.job.control.cancel();
        }
        result
    }

    /// Write the cursor inside a transaction someone else drives (the scan's hit commits).
    pub fn checkpoint_in<C: Cursor>(&self, w: &CaseWriter<'_>, cursor: &C) -> Result<()> {
        self.faults.before_commit(self.job.kind)?;
        let json = serde_json::json!({ "note": cursor.note(), "cursor": cursor });
        let p = self.job.control.snapshot();
        w.job_checkpoint(self.job.id.0, &json.to_string(), p.scanned, p.total)?;
        *self.job.checkpoint.lock() = super::Checkpoint { json: Some(json), saved_at: Some(unix_now()) };
        *self.last_commit.lock() = Instant::now();
        self.pending.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// The evidence, counting bytes read into the job's I/O cost.
    pub fn source(&self) -> Result<Arc<dyn BlockSource>> {
        Ok(Arc::new(CountingSource { inner: self.case.source(self.job.evidence)?, control: self.job.control.clone() }))
    }
}

/// Read-through wrapper that adds every read to the job's evidence-bytes counter.
struct CountingSource {
    inner: Arc<dyn BlockSource>,
    control: Arc<ScanControl>,
}

impl BlockSource for CountingSource {
    fn info(&self) -> SourceInfo {
        self.inner.info()
    }

    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.read_at(offset, buf)?;
        self.control.add_read(n as u64);
        Ok(n)
    }

    fn damage(&self) -> Vec<ByteRange> {
        self.inner.damage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobId, JobState};

    #[derive(Serialize, serde::Deserialize, Default, Debug, PartialEq)]
    struct Count {
        n: u32,
    }

    impl Cursor for Count {
        fn note(&self) -> String {
            format!("from item {}", self.n)
        }
    }

    fn job(case: &Case) -> Job {
        let id = case.add_job(1, EvidenceId::new(1), "Carve", "t", "Running").unwrap();
        Job::new(JobId(id), JobKind::Carve, EvidenceId::new(1), None, JobState::Running)
    }

    #[test]
    fn commit_stores_cursor_and_results_together_and_ticks_by_items() {
        let dir = tempfile::tempdir().unwrap();
        let case = Case::open(&dir.path().join("c.strata")).unwrap();
        let job = job(&case);
        let faults = Faults::default();
        let policy = CheckpointPolicy { every: Duration::from_secs(3600), every_items: 3 };
        let ctx = StepContext::new(&case, &job, policy, &faults);
        assert_eq!(ctx.cursor::<Count>(), None);
        assert!(!ctx.tick(1) && !ctx.tick(1));
        assert!(ctx.tick(1), "the third unit makes a checkpoint due");
        ctx.commit(&Count { n: 3 }, |_| Ok(())).unwrap();
        assert!(!ctx.tick(1), "a commit resets the budget");
        assert_eq!(ctx.cursor::<Count>(), Some(Count { n: 3 }));
        let stored = case.job(job.id.0).unwrap().unwrap().checkpoint.unwrap();
        assert!(stored.contains("from item 3"), "{stored}");
        assert_eq!(job.view().checkpoint.unwrap().note, "from item 3");
    }

    #[test]
    fn a_simulated_crash_drops_the_commit_and_everything_after() {
        let dir = tempfile::tempdir().unwrap();
        let case = Case::open(&dir.path().join("c.strata")).unwrap();
        let job = job(&case);
        let faults = Faults::default();
        faults.crash_after(JobKind::Carve, 1);
        let ctx = StepContext::new(&case, &job, CheckpointPolicy::default(), &faults);
        ctx.commit(&Count { n: 1 }, |_| Ok(())).unwrap();
        assert!(ctx.commit(&Count { n: 2 }, |_| Ok(())).is_err());
        assert!(faults.is_dead() && job.control.is_cancelled());
        let stored = case.job(job.id.0).unwrap().unwrap().checkpoint.unwrap();
        assert!(stored.contains("from item 1"));
    }
}
