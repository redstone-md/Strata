use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Called on every thread that starts working for a job (scanner workers, the collector, the
/// step's own thread), so observers can attribute CPU time to the job.
pub type ThreadHook = Arc<dyn Fn() + Send + Sync>;

/// Shared handle between a running step and its observers (UI, CLI, job manager): progress,
/// cancel, pause, the item being worked on and the evidence bytes read.
pub struct ScanControl {
    cancel: AtomicBool,
    paused: Mutex<bool>,
    unpaused: Condvar,
    total: AtomicU64,
    scanned: AtomicU64,
    /// Progress already done before this run started (a resumed step); not part of the rate.
    base: AtomicU64,
    hits: AtomicU64,
    read: AtomicU64,
    /// Every byte below the watermark has been scanned; safe resume point.
    watermark: AtomicU64,
    finished_chunks: Mutex<BTreeMap<u64, u64>>,
    clock: Mutex<Clock>,
    current: Mutex<String>,
    thread_hook: Mutex<Option<ThreadHook>>,
}

/// Wall time the step has been working, excluding pauses.
#[derive(Default)]
struct Clock {
    started: Option<Instant>,
    paused_at: Option<Instant>,
    paused_for: Duration,
}

impl Clock {
    fn active(&self) -> Duration {
        let Some(started) = self.started else { return Duration::ZERO };
        let pausing = self.paused_at.map_or(Duration::ZERO, |p| p.elapsed());
        started.elapsed().saturating_sub(self.paused_for + pausing)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ScanSnapshot {
    /// Work units of the step: bytes for scans, items for item-counting steps.
    pub total: u64,
    pub scanned: u64,
    pub hits: u64,
    pub watermark: u64,
    /// Units per second over this run's active (unpaused) time.
    pub per_sec: f64,
    /// Evidence bytes read by this run.
    pub read_bytes: u64,
    pub elapsed_secs: f64,
    pub cancelled: bool,
    pub paused: bool,
}

impl Default for ScanControl {
    fn default() -> Self {
        Self {
            cancel: AtomicBool::new(false),
            paused: Mutex::new(false),
            unpaused: Condvar::new(),
            total: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            base: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            read: AtomicU64::new(0),
            watermark: AtomicU64::new(0),
            finished_chunks: Mutex::new(BTreeMap::new()),
            clock: Mutex::new(Clock::default()),
            current: Mutex::new(String::new()),
            thread_hook: Mutex::new(None),
        }
    }
}

impl ScanControl {
    /// Stop as soon as possible; also releases a paused step.
    pub fn cancel(&self) {
        let _paused = self.paused.lock();
        self.cancel.store(true, Ordering::Relaxed);
        self.unpaused.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Workers block at their next check until [`resume`](Self::resume) or cancel.
    pub fn pause(&self) {
        let mut paused = self.paused.lock();
        if !*paused {
            *paused = true;
            self.clock.lock().paused_at = Some(Instant::now());
        }
    }

    pub fn resume(&self) {
        let mut paused = self.paused.lock();
        if *paused {
            *paused = false;
            let mut clock = self.clock.lock();
            if let Some(at) = clock.paused_at.take() {
                clock.paused_for += at.elapsed();
            }
            self.unpaused.notify_all();
        }
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.lock()
    }

    /// The check every worker makes between units of work: blocks while paused, then tells
    /// whether to stop.
    pub fn should_stop(&self) -> bool {
        let mut paused = self.paused.lock();
        while *paused && !self.is_cancelled() {
            self.unpaused.wait(&mut paused);
        }
        self.is_cancelled()
    }

    pub fn snapshot(&self) -> ScanSnapshot {
        let scanned = self.scanned.load(Ordering::Relaxed);
        let done_now = scanned.saturating_sub(self.base.load(Ordering::Relaxed));
        let elapsed = self.clock.lock().active().as_secs_f64();
        ScanSnapshot {
            total: self.total.load(Ordering::Relaxed),
            scanned,
            hits: self.hits.load(Ordering::Relaxed),
            watermark: self.watermark.load(Ordering::Relaxed),
            per_sec: if elapsed > 0.0 { done_now as f64 / elapsed } else { 0.0 },
            read_bytes: self.read.load(Ordering::Relaxed),
            elapsed_secs: elapsed,
            cancelled: self.is_cancelled(),
            paused: self.is_paused(),
        }
    }

    /// Start counting `total` units of which `done` are already finished (a resumed step).
    pub fn begin_at(&self, done: u64, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.scanned.store(done, Ordering::Relaxed);
        self.base.store(done, Ordering::Relaxed);
        self.watermark.store(done, Ordering::Relaxed);
        self.finished_chunks.lock().clear();
        let paused = self.is_paused();
        let mut clock = self.clock.lock();
        *clock = Clock { started: Some(Instant::now()), ..Clock::default() };
        if paused {
            clock.paused_at = Some(Instant::now());
        }
    }

    /// Reuse the control for item-counting jobs (e.g. network lookups).
    pub fn begin_items(&self, total: u64) {
        self.begin_at(0, total);
    }

    pub fn item_done(&self) {
        self.items_done(1);
    }

    pub fn items_done(&self, n: u64) {
        self.scanned.fetch_add(n, Ordering::Relaxed);
        self.watermark.fetch_add(n, Ordering::Relaxed);
    }

    /// Evidence bytes read for this step (shown as I/O cost).
    pub fn add_read(&self, bytes: u64) {
        self.read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// What is being worked on, in words: a file path, an offset, an archive member.
    pub fn set_current(&self, item: &str) {
        let mut current = self.current.lock();
        current.clear();
        current.push_str(item);
    }

    pub fn current(&self) -> String {
        self.current.lock().clone()
    }

    /// Install the hook run by [`enter_thread`](Self::enter_thread).
    pub fn set_thread_hook(&self, hook: ThreadHook) {
        *self.thread_hook.lock() = Some(hook);
    }

    /// Announce that the calling thread now works for this control's job.
    pub fn enter_thread(&self) {
        let hook = self.thread_hook.lock().clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn add_hits(&self, n: u64) {
        self.hits.fetch_add(n, Ordering::Relaxed);
    }

    /// Record a finished chunk `[start, end)` and advance the contiguous watermark.
    pub(crate) fn chunk_done(&self, start: u64, end: u64) {
        self.scanned.fetch_add(end - start, Ordering::Relaxed);
        let mut pending = self.finished_chunks.lock();
        pending.insert(start, end);
        let mut mark = self.watermark.load(Ordering::Relaxed);
        while let Some(next) = pending.remove(&mark) {
            mark = next;
        }
        self.watermark.store(mark, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn pause_blocks_until_resumed_and_cancel_releases() {
        let control = Arc::new(ScanControl::default());
        control.begin_items(10);
        control.pause();
        let passed = Arc::new(AtomicUsize::new(0));
        let worker = {
            let (control, passed) = (control.clone(), passed.clone());
            std::thread::spawn(move || {
                while !control.should_stop() {
                    passed.fetch_add(1, Ordering::SeqCst);
                    control.item_done();
                    if control.snapshot().scanned >= 10 {
                        break;
                    }
                }
            })
        };
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(passed.load(Ordering::SeqCst), 0, "a paused worker does no work");
        assert!(control.snapshot().paused);
        control.resume();
        worker.join().unwrap();
        assert_eq!(passed.load(Ordering::SeqCst), 10);

        control.pause();
        let blocked = {
            let control = control.clone();
            std::thread::spawn(move || control.should_stop())
        };
        std::thread::sleep(Duration::from_millis(30));
        control.cancel();
        assert!(blocked.join().unwrap(), "cancel wakes a paused worker and stops it");
    }

    #[test]
    fn resumed_progress_does_not_inflate_the_rate() {
        let control = ScanControl::default();
        control.begin_at(900, 1000);
        std::thread::sleep(Duration::from_millis(20));
        control.items_done(10);
        let s = control.snapshot();
        assert_eq!((s.scanned, s.total), (910, 1000));
        assert!(s.per_sec < 10.0 / 0.019, "rate counts only this run's 10 units: {}", s.per_sec);
    }

    #[test]
    fn paused_time_is_not_working_time() {
        let control = ScanControl::default();
        control.begin_items(1);
        control.pause();
        std::thread::sleep(Duration::from_millis(60));
        control.resume();
        assert!(control.snapshot().elapsed_secs < 0.05);
    }

    #[test]
    fn thread_hook_runs_on_enter() {
        let control = ScanControl::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        control.set_thread_hook(Arc::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        control.enter_thread();
        std::thread::scope(|s| {
            s.spawn(|| control.enter_thread());
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        control.set_current("a/b.txt");
        assert_eq!(control.current(), "a/b.txt");
    }
}
