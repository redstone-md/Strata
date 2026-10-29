//! What a front-end sees of a job: an immutable snapshot plus the arithmetic on it.

use super::{Job, JobId, JobKind, JobState};
use serde::Serialize;
use std::time::Duration;
use strata_engine::ScanSnapshot;
use strata_kernel::EvidenceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProgressUnit {
    Bytes,
    Items,
}

/// The last saved resume point, in words.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckpointInfo {
    /// Unix seconds.
    pub saved_at: i64,
    /// What a resumed run continues from ("volume 2, from file 1,204").
    pub note: String,
}

/// Immutable snapshot for rendering.
#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: JobId,
    pub kind: JobKind,
    pub evidence: EvidenceId,
    pub title: String,
    pub pipeline: Option<JobId>,
    pub state: JobState,
    pub progress: ScanSnapshot,
    pub unit: ProgressUnit,
    /// Item being worked on right now (empty when idle).
    pub current: String,
    pub checkpoint: Option<CheckpointInfo>,
    /// Unix seconds.
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    /// Pid of another live process running this job.
    pub foreign: Option<u32>,
}

impl JobView {
    pub(super) fn of(job: &Job) -> Self {
        let checkpoint = job.checkpoint.lock().clone();
        let times = *job.times.lock();
        let note = checkpoint.json.as_ref().and_then(|j| j.get("note")).and_then(|n| n.as_str()).map(str::to_string);
        Self {
            id: job.id,
            kind: job.kind,
            evidence: job.evidence,
            title: job.title.clone(),
            pipeline: job.pipeline,
            state: job.state.lock().clone(),
            progress: job.control.snapshot(),
            unit: job.kind.unit(),
            current: job.control.current(),
            checkpoint: checkpoint.saved_at.zip(note).map(|(saved_at, note)| CheckpointInfo { saved_at, note }),
            created_at: times.created,
            started_at: times.started,
            finished_at: times.finished,
            foreign: job.foreign,
        }
    }

    /// 0..=1 completion.
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if p.total == 0 {
            return if matches!(self.state, JobState::Done(_)) { 1.0 } else { 0.0 };
        }
        (p.scanned as f64 / p.total as f64).clamp(0.0, 1.0) as f32
    }

    pub fn is_paused(&self) -> bool {
        self.state == JobState::Running && self.progress.paused
    }

    /// Time left at the current rate, while running.
    pub fn eta(&self) -> Option<Duration> {
        (self.state == JobState::Running && !self.progress.paused)
            .then(|| eta(self.progress.scanned, self.progress.total, self.progress.per_sec))
            .flatten()
    }
}

/// Time to finish `total` units with `done` finished at `per_sec` units per second; `None`
/// while there is no rate or no known total.
pub fn eta(done: u64, total: u64, per_sec: f64) -> Option<Duration> {
    if total == 0 || !per_sec.is_finite() || per_sec <= 0.0 {
        return None;
    }
    let left = total.saturating_sub(done) as f64 / per_sec;
    // Anything beyond a year is noise from a stalled rate.
    (left < 365.0 * 86_400.0).then(|| Duration::from_secs_f64(left))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_is_remaining_over_rate() {
        assert_eq!(eta(250, 1000, 50.0), Some(Duration::from_secs(15)));
        assert_eq!(eta(1000, 1000, 50.0), Some(Duration::ZERO));
        assert_eq!(eta(1200, 1000, 50.0), Some(Duration::ZERO));
        assert_eq!(eta(10, 1000, 0.0), None);
        assert_eq!(eta(10, 0, 5.0), None);
        assert_eq!(eta(0, u64::MAX, 1e-9), None);
        assert_eq!(eta(0, 10, f64::NAN), None);
    }
}
