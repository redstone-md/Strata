//! Running jobs: the analyse pipeline on a background thread, single steps in the foreground,
//! resuming interrupted work, pausing and stopping.

use super::context::{CheckpointPolicy, StepContext};
use super::{Job, JobId, JobKind, JobState, JobView, StopReason};
use crate::Workbench;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_kernel::{EvidenceId, Result};

impl Workbench {
    /// The standard "analyse this disk" pipeline ([`JobKind::PIPELINE`]) on a background
    /// thread. Every step is queued (and persisted) up front, so a crash resumes the rest.
    /// Returns the scan job's id.
    pub fn analyse(self: &Arc<Self>, evidence: EvidenceId) -> Result<JobId> {
        let jobs = self.queue.enqueue(&self.case, evidence, &JobKind::PIPELINE)?;
        let scan = jobs.iter().find(|j| j.kind == JobKind::Scan).map_or(jobs[0].id, |j| j.id);
        self.spawn(jobs);
        Ok(scan)
    }

    /// Run one pipeline step in the foreground (CLI, re-running a step after an upgrade).
    pub fn run_step(&self, kind: JobKind, evidence: EvidenceId) -> Result<JobView> {
        let job = self.queue.enqueue(&self.case, evidence, &[kind])?.remove(0);
        self.run_job(&job);
        Ok(job.view())
    }

    /// Bring a case made by an older version up to date in the background, per disk:
    /// below rules version 2 a scanned disk re-checks its findings (`Recheck`); below 3 a disk
    /// with a file listing reads its mail (`Mail`). Returns how many jobs were queued.
    pub fn recheck_if_rules_changed(self: &Arc<Self>) -> Result<usize> {
        let stored: u32 = self.case.setting(Self::RULES_KEY)?.and_then(|v| v.parse().ok()).unwrap_or(1);
        if stored >= Self::RULES_VERSION {
            return Ok(0);
        }
        let mut queued = 0;
        for disk in self.case.evidence()? {
            let mut kinds = Vec::new();
            let scanned = self.case.scan_state(disk.id)?.is_some();
            // Detector rules changed in versions 2, 5, 7 and 8; Recheck also tidies (repeat cap
            // and triage, changed in 4).
            if stored < 8 && scanned {
                kinds.push(JobKind::Recheck);
            }
            let indexed = self.case.has_files(disk.id)?;
            // Version 6 parses more of the registry and Linux system files (machine profiles).
            if stored < 6 && indexed {
                kinds.push(JobKind::Artifacts);
            }
            if stored < 3 && indexed {
                kinds.push(JobKind::Mail);
            }
            if !kinds.is_empty() {
                queued += kinds.len();
                self.spawn(self.queue.enqueue(&self.case, disk.id, &kinds)?);
            }
        }
        self.case.set_setting(Self::RULES_KEY, &Self::RULES_VERSION.to_string())?;
        Ok(queued)
    }

    /// Continue every interrupted job from its checkpoint, pipelines in order. Returns how
    /// many jobs were picked up.
    pub fn resume_interrupted(self: &Arc<Self>) -> usize {
        let groups = self.queue.interrupted();
        let n = groups.iter().map(Vec::len).sum();
        for group in groups {
            for job in &group {
                self.queue.set_state(&self.case, job, JobState::Queued);
            }
            self.spawn(group);
        }
        n
    }

    pub fn cancel_job(&self, id: JobId) {
        if let Some(j) = self.queue.get(id) {
            j.cancel();
        }
    }

    /// Hold a running job: its workers block at their next check.
    pub fn pause_job(&self, id: JobId) {
        if let Some(j) = self.queue.get(id).filter(|j| j.is_active()) {
            j.control.pause();
            j.log.push("paused");
        }
    }

    pub fn resume_job(&self, id: JobId) {
        if let Some(j) = self.queue.get(id).filter(|j| j.control.is_paused()) {
            j.control.resume();
            j.log.push("resumed");
        }
    }

    /// Stop all work because the app is closing: running jobs save their checkpoint and end
    /// as interrupted, queued ones stay queued; both resume on the next start. Waits up to
    /// `wait` for the steps to reach their checkpoint.
    pub fn shutdown(&self, wait: Duration) {
        for job in self.queue.all().iter().filter(|j| j.is_active()) {
            job.stop(StopReason::Shutdown);
        }
        let until = Instant::now() + wait;
        while self.queue.all().iter().any(|j| j.foreign.is_none() && *j.state.lock() == JobState::Running) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Change how often steps save checkpoints (tests use tiny batches).
    #[doc(hidden)]
    pub fn set_checkpoint_policy(&self, policy: CheckpointPolicy) {
        *self.policy.lock() = policy;
    }

    /// Crash-test hook: after `commits` checkpoint commits of `kind` the process "dies" — no
    /// later write of results or job state reaches the case.
    #[doc(hidden)]
    pub fn crash_after_commits(&self, kind: JobKind, commits: u32) {
        self.queue.faults.crash_after(kind, commits);
    }

    fn spawn(self: &Arc<Self>, jobs: Vec<Arc<Job>>) {
        let this = self.clone();
        let name = format!("pipeline-{}", jobs.first().map_or(0, |j| j.id.0));
        let spawned = std::thread::Builder::new().name(name).spawn(move || this.run_pipeline(&jobs));
        if let Err(e) = spawned {
            for job in self.queue.all().iter().filter(|j| *j.state.lock() == JobState::Queued) {
                self.queue.set_state(&self.case, job, JobState::Failed(format!("cannot start a worker thread: {e}")));
            }
        }
    }

    fn run_pipeline(&self, jobs: &[Arc<Job>]) {
        for (i, job) in jobs.iter().enumerate() {
            self.run_job(job);
            let state = job.state.lock().clone();
            let rest = match state {
                // Closing or crashed: the rest resumes with this one.
                JobState::Interrupted => JobState::Interrupted,
                JobState::Cancelled => JobState::Cancelled,
                // Follow-ups need a finished scan.
                JobState::Failed(_) if job.kind == JobKind::Scan => JobState::Cancelled,
                _ => continue,
            };
            for later in &jobs[i + 1..] {
                self.queue.set_state(&self.case, later, rest.clone());
            }
            return;
        }
    }

    /// Queue a job that carries parameters in its starting cursor and run it in the
    /// background; it resumes like any other job.
    pub(crate) fn start_job<C: super::context::Cursor>(self: &Arc<Self>, kind: JobKind, evidence: EvidenceId, title: &str, cursor: &C) -> Result<JobId> {
        let job = self.queue.enqueue_with(&self.case, evidence, kind, title, cursor)?;
        let id = job.id;
        self.spawn(vec![job]);
        Ok(id)
    }

    fn run_job(&self, job: &Job) {
        let resumed = job.times.lock().started.is_some() && job.checkpoint.lock().json.is_some();
        if job.control.is_cancelled() {
            return self.finish(job, Ok(String::new()));
        }
        self.queue.set_state(&self.case, job, JobState::Running);
        job.control.enter_thread();
        job.log.push(match job.view().checkpoint {
            Some(c) if resumed => format!("resumed from {}", c.note),
            _ => "started".to_string(),
        });
        let policy = *self.policy.lock();
        let ctx = StepContext::new(&self.case, job, policy, &self.queue.faults);
        let result = crate::steps::run(&ctx, job.kind, self);
        job.threads.release_current();
        job.control.set_current("");
        self.finish(job, result);
    }

    fn finish(&self, job: &Job, result: Result<String>) {
        let state = if self.queue.faults.is_dead() {
            JobState::Interrupted
        } else {
            match (job.stop_reason(), result) {
                (super::StopReason::Shutdown, _) => JobState::Interrupted,
                (super::StopReason::Cancel, _) => JobState::Cancelled,
                (_, Err(e)) => JobState::Failed(e.to_string()),
                (_, Ok(msg)) => JobState::Done(msg),
            }
        };
        job.log.push(match &state {
            JobState::Done(msg) => format!("done: {msg}"),
            JobState::Failed(e) => format!("failed: {e}"),
            JobState::Interrupted => "interrupted; resumes from its checkpoint".to_string(),
            _ => "cancelled".to_string(),
        });
        self.queue.set_state(&self.case, job, state);
    }
}
