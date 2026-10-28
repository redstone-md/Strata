use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Shared handle between a running scan and its observers (UI, CLI, job manager).
pub struct ScanControl {
    cancel: AtomicBool,
    total: AtomicU64,
    scanned: AtomicU64,
    hits: AtomicU64,
    /// Every byte below the watermark has been scanned; safe resume point.
    watermark: AtomicU64,
    finished_chunks: Mutex<BTreeMap<u64, u64>>,
    started: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub total: u64,
    pub scanned: u64,
    pub hits: u64,
    pub watermark: u64,
    pub bytes_per_sec: f64,
    pub cancelled: bool,
}

impl Default for ScanControl {
    fn default() -> Self {
        Self {
            cancel: AtomicBool::new(false),
            total: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            watermark: AtomicU64::new(0),
            finished_chunks: Mutex::new(BTreeMap::new()),
            started: Mutex::new(None),
        }
    }
}

impl ScanControl {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> ScanSnapshot {
        let scanned = self.scanned.load(Ordering::Relaxed);
        let elapsed = self.started.lock().map_or(0.0, |s| s.elapsed().as_secs_f64());
        ScanSnapshot {
            total: self.total.load(Ordering::Relaxed),
            scanned,
            hits: self.hits.load(Ordering::Relaxed),
            watermark: self.watermark.load(Ordering::Relaxed),
            bytes_per_sec: if elapsed > 0.0 { scanned as f64 / elapsed } else { 0.0 },
            cancelled: self.is_cancelled(),
        }
    }

    pub(crate) fn begin(&self, start: u64, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.scanned.store(0, Ordering::Relaxed);
        self.watermark.store(start, Ordering::Relaxed);
        self.finished_chunks.lock().clear();
        *self.started.lock() = Some(Instant::now());
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
