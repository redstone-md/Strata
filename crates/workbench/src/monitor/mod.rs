//! What Strata costs right now: process CPU, memory, disk I/O, threads and GPU, CPU of each
//! job's own threads, and the machine around it. Sampled once a second into ten-minute rings,
//! only while someone watches (the Tasks screen, `strata-cli top`) or a job runs.

mod gpu;
mod probe;
mod ring;
mod threads;

pub use probe::SystemSample;
pub(crate) use probe::is_strata_process;
use ring::Ring;
pub(crate) use threads::ThreadSet;

use crate::jobs::{JobId, JobState};
use crate::jobs::queue::JobQueue;
use gpu::GpuProbe;
use parking_lot::Mutex;
use probe::ProcessProbe;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

/// Sampling period.
pub const PERIOD: Duration = Duration::from_secs(1);
/// Samples kept: ten minutes.
const HISTORY: usize = 600;

/// One process-wide sample.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ResourceSample {
    /// Seconds since the monitor started.
    pub at: f64,
    /// 0..=100 of all cores.
    pub cpu: f32,
    pub working_set: u64,
    pub private_bytes: u64,
    pub read_per_sec: f64,
    pub write_per_sec: f64,
    pub threads: Option<u32>,
    /// 0..=100, busiest GPU engine type.
    pub gpu: Option<f32>,
    pub gpu_memory: Option<u64>,
}

/// One sample of one job.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct JobSample {
    pub at: f64,
    /// 0..=100 of all cores, from the job's own threads (or its share of the process).
    pub cpu: f32,
    pub read_per_sec: f64,
    pub units_per_sec: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MonitorView {
    /// Oldest first.
    pub process: Vec<ResourceSample>,
    pub system: Option<SystemSample>,
    pub jobs: HashMap<JobId, Vec<JobSample>>,
    pub cores: usize,
    /// Job CPU comes from the job's own threads (else: its share of the process).
    pub per_thread_cpu: bool,
    pub gpu_available: bool,
}

impl MonitorView {
    pub fn latest(&self) -> Option<&ResourceSample> {
        self.process.last()
    }

    pub fn job_latest(&self, id: JobId) -> Option<&JobSample> {
        self.jobs.get(&id).and_then(|s| s.last())
    }
}

struct JobTrack {
    samples: Ring<JobSample>,
    cpu: Option<Duration>,
    read: u64,
    units: u64,
}

struct State {
    process: Ring<ResourceSample>,
    system: Option<SystemSample>,
    jobs: HashMap<JobId, JobTrack>,
    per_thread_cpu: bool,
    gpu_available: bool,
    cores: usize,
}

struct Shared {
    state: Mutex<State>,
    watchers: AtomicUsize,
}

/// Handle to the sampling thread; the thread ends with the job queue it watches.
#[derive(Clone)]
pub struct Monitor {
    shared: Arc<Shared>,
}

impl Monitor {
    pub(crate) fn start(queue: Weak<JobQueue>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                process: Ring::new(HISTORY),
                system: None,
                jobs: HashMap::new(),
                per_thread_cpu: cfg!(windows),
                gpu_available: false,
                cores: 1,
            }),
            watchers: AtomicUsize::new(0),
        });
        let worker = shared.clone();
        let _ = std::thread::Builder::new().name("strata-monitor".into()).spawn(move || Sampler::new(worker).run(queue));
        Self { shared }
    }

    /// Someone looks at the numbers: sample even while no job runs. Pair with [`unwatch`](Self::unwatch).
    pub fn watch(&self) {
        self.shared.watchers.fetch_add(1, Ordering::SeqCst);
    }

    pub fn unwatch(&self) {
        let w = &self.shared.watchers;
        let mut n = w.load(Ordering::SeqCst);
        while n > 0 {
            match w.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(now) => n = now,
            }
        }
    }

    pub fn view(&self) -> MonitorView {
        let s = self.shared.state.lock();
        MonitorView {
            process: s.process.to_vec(),
            system: s.system,
            jobs: s.jobs.iter().map(|(id, t)| (*id, t.samples.to_vec())).collect(),
            cores: s.cores,
            per_thread_cpu: s.per_thread_cpu,
            gpu_available: s.gpu_available,
        }
    }
}

/// Readings of one process (this one, or the one running a case's jobs): CPU, memory, disk
/// I/O, threads and GPU, plus the machine around it.
pub struct ProcessWatch {
    process: ProcessProbe,
    gpu: Option<GpuProbe>,
    started: Instant,
}

impl ProcessWatch {
    pub fn new(pid: u32) -> Self {
        Self { process: ProcessProbe::new(pid), gpu: GpuProbe::open(pid), started: Instant::now() }
    }

    pub fn cores(&self) -> usize {
        self.process.cores()
    }

    pub fn gpu_available(&self) -> bool {
        self.gpu.is_some()
    }

    /// Reading since the previous call; the first call only primes the counters.
    pub fn sample(&mut self) -> Option<(ResourceSample, SystemSample)> {
        let (p, system) = self.process.sample()?;
        let gpu = self.gpu.as_mut().map(GpuProbe::sample).unwrap_or_default();
        let sample = ResourceSample {
            at: self.started.elapsed().as_secs_f64(),
            cpu: p.cpu,
            working_set: p.working_set,
            private_bytes: p.private_bytes,
            read_per_sec: p.read_per_sec,
            write_per_sec: p.write_per_sec,
            threads: p.threads,
            gpu: gpu.utilization,
            gpu_memory: gpu.dedicated_bytes,
        };
        Some((sample, system))
    }

    /// Forget the previous reading (after an idle period, so rates do not average over it).
    pub fn reset(&mut self) {
        self.process.reset();
    }
}

struct Sampler {
    shared: Arc<Shared>,
    last: Option<Instant>,
    watch: ProcessWatch,
}

impl Sampler {
    fn new(shared: Arc<Shared>) -> Self {
        let watch = ProcessWatch::new(std::process::id());
        {
            let mut s = shared.state.lock();
            s.cores = watch.cores();
            s.gpu_available = watch.gpu_available();
        }
        Self { shared, last: None, watch }
    }

    fn run(mut self, queue: Weak<JobQueue>) {
        loop {
            std::thread::sleep(PERIOD);
            let Some(queue) = queue.upgrade() else { return };
            let wanted = self.shared.watchers.load(Ordering::SeqCst) > 0 || queue.has_active();
            if wanted {
                self.sample(&queue);
            } else if self.last.take().is_some() {
                self.watch.reset();
            }
        }
    }

    fn sample(&mut self, queue: &JobQueue) {
        let now = Instant::now();
        let dt = self.last.replace(now).map(|t| now.duration_since(t).as_secs_f64());
        let Some((mut sample, system)) = self.watch.sample() else { return };
        let at = sample.at;
        let running: Vec<_> =
            queue.all().into_iter().filter(|j| j.foreign.is_none() && *j.state.lock() == JobState::Running).collect();
        let mut s = self.shared.state.lock();
        let cores = s.cores.max(1) as f64;
        let mut evidence_read = 0.0;
        let share = if running.is_empty() { 0.0 } else { sample.cpu / running.len() as f32 };
        for job in &running {
            let snap = job.control.snapshot();
            let cpu = job.threads.cpu_time();
            let Some(track) = s.jobs.get_mut(&job.id) else {
                // First sight of the job: only a baseline, no rate yet.
                s.jobs.insert(job.id, JobTrack { samples: Ring::new(HISTORY), cpu, read: snap.read_bytes, units: snap.scanned });
                continue;
            };
            let rate = |now: f64| dt.filter(|d| *d > 0.0).map_or(0.0, |d| now / d);
            let job_cpu = match (cpu, track.cpu) {
                (Some(c), Some(prev)) => rate(c.saturating_sub(prev).as_secs_f64()) / cores * 100.0,
                _ => f64::from(share),
            };
            let read_per_sec = rate(snap.read_bytes.saturating_sub(track.read) as f64);
            evidence_read += read_per_sec;
            track.samples.push(JobSample {
                at,
                cpu: job_cpu.clamp(0.0, 100.0) as f32,
                read_per_sec,
                units_per_sec: rate(snap.scanned.saturating_sub(track.units) as f64),
            });
            (track.cpu, track.read, track.units) = (cpu, snap.read_bytes, snap.scanned);
        }
        // Reads served from the file cache skip the OS I/O counters; evidence reads the jobs
        // counted themselves are a floor for what the process read.
        sample.read_per_sec = sample.read_per_sec.max(evidence_read);
        s.process.push(sample);
        s.system = Some(system);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_sees_this_process_work() {
        let mut watch = ProcessWatch::new(std::process::id());
        assert!(watch.sample().is_none(), "the first reading only primes the counters");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blob");
        std::fs::write(&file, vec![7u8; 8 << 20]).unwrap();
        assert_eq!(std::fs::read(&file).unwrap().len(), 8 << 20);
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed() < Duration::from_millis(600) {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(1));
        }
        let (p, s) = watch.sample().expect("second reading");
        assert!(p.cpu > 0.5, "a busy thread shows: {p:?}");
        assert!(p.working_set > 0 && s.total_ram > 0);
        assert!(p.write_per_sec > 0.0, "the write shows: {p:?}");
        assert!(p.read_per_sec > 0.0, "the read shows: {p:?}");
    }

    #[test]
    fn job_samples_rate_cpu_and_evidence_reads() {
        let dir = tempfile::tempdir().unwrap();
        let case = strata_case::Case::open(&dir.path().join("m.strata")).unwrap();
        let queue = JobQueue::default();
        let job = queue.enqueue(&case, strata_kernel::EvidenceId::new(1), &[crate::JobKind::Scan]).unwrap().remove(0);
        *job.state.lock() = JobState::Running;
        job.control.begin_at(0, 1000);
        job.control.enter_thread();
        let monitor = Monitor::start(std::sync::Weak::new());
        let mut sampler = Sampler::new(monitor.shared.clone());
        sampler.sample(&queue);
        sampler.sample(&queue);
        assert!(monitor.view().jobs.get(&job.id).is_none_or(|s| s.is_empty()), "first sight is only a baseline");
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed() < Duration::from_millis(300) {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(1));
        }
        job.control.add_read(64 << 20);
        job.control.items_done(500);
        sampler.sample(&queue);
        let view = monitor.view();
        let s = view.job_latest(job.id).copied().expect("a job sample");
        assert!(s.cpu > 0.0, "{s:?}");
        assert!(s.read_per_sec > 1e6 && s.units_per_sec > 100.0, "{s:?}");
        let p = view.latest().copied().unwrap();
        assert!(p.read_per_sec >= s.read_per_sec, "evidence reads are a floor for the process: {p:?}");
    }
}
