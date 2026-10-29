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

struct Sampler {
    shared: Arc<Shared>,
    started: Instant,
    last: Option<Instant>,
    process: ProcessProbe,
    gpu: Option<GpuProbe>,
}

impl Sampler {
    fn new(shared: Arc<Shared>) -> Self {
        let pid = std::process::id();
        let process = ProcessProbe::new(pid);
        let gpu = GpuProbe::open(pid);
        {
            let mut s = shared.state.lock();
            s.cores = process.cores();
            s.gpu_available = gpu.is_some();
        }
        Self { shared, started: Instant::now(), last: None, process, gpu }
    }

    fn run(mut self, queue: Weak<JobQueue>) {
        loop {
            std::thread::sleep(PERIOD);
            let Some(queue) = queue.upgrade() else { return };
            let wanted = self.shared.watchers.load(Ordering::SeqCst) > 0 || queue.has_active();
            if wanted {
                self.sample(&queue);
            } else if self.last.take().is_some() {
                self.process.reset();
            }
        }
    }

    fn sample(&mut self, queue: &JobQueue) {
        let now = Instant::now();
        let dt = self.last.replace(now).map(|t| now.duration_since(t).as_secs_f64());
        let Some((p, system)) = self.process.sample() else { return };
        let gpu = self.gpu.as_mut().map(GpuProbe::sample).unwrap_or_default();
        let at = now.duration_since(self.started).as_secs_f64();
        let sample = ResourceSample {
            at,
            cpu: p.cpu,
            working_set: p.working_set,
            private_bytes: p.private_bytes,
            read_per_sec: p.read_per_sec,
            write_per_sec: p.write_per_sec,
            threads: p.threads,
            gpu: gpu.utilization,
            gpu_memory: gpu.dedicated_bytes,
        };
        let running: Vec<_> =
            queue.all().into_iter().filter(|j| j.foreign.is_none() && *j.state.lock() == JobState::Running).collect();
        let mut s = self.shared.state.lock();
        let cores = s.cores.max(1) as f64;
        s.process.push(sample);
        s.system = Some(system);
        let share = if running.is_empty() { 0.0 } else { p.cpu / running.len() as f32 };
        for job in &running {
            let snap = job.control.snapshot();
            let cpu = job.threads.cpu_time();
            let track = s.jobs.entry(job.id).or_insert_with(|| JobTrack { samples: Ring::new(HISTORY), cpu, read: snap.read_bytes, units: snap.scanned });
            let rate = |now: f64| dt.filter(|d| *d > 0.0).map_or(0.0, |d| now / d);
            let job_cpu = match (cpu, track.cpu) {
                (Some(c), Some(prev)) => rate(c.saturating_sub(prev).as_secs_f64()) / cores * 100.0,
                _ => f64::from(share),
            };
            track.samples.push(JobSample {
                at,
                cpu: job_cpu.clamp(0.0, 100.0) as f32,
                read_per_sec: rate(snap.read_bytes.saturating_sub(track.read) as f64),
                units_per_sec: rate(snap.scanned.saturating_sub(track.units) as f64),
            });
            (track.cpu, track.read, track.units) = (cpu, snap.read_bytes, snap.scanned);
        }
    }
}
