//! Process-wide and system readings: memory, disk I/O and the machine through `sysinfo`; on
//! Windows process CPU through `GetProcessTimes` and the thread count through a Toolhelp
//! snapshot.

use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// One reading of a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessReading {
    /// 0..=100, normalised to all cores.
    pub cpu: f32,
    pub working_set: u64,
    pub private_bytes: u64,
    pub read_per_sec: f64,
    pub write_per_sec: f64,
    pub threads: Option<u32>,
}

/// One reading of the machine.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct SystemSample {
    /// 0..=100 over all cores.
    pub cpu: f32,
    pub free_ram: u64,
    pub total_ram: u64,
}

pub struct ProcessProbe {
    sys: System,
    pid: Pid,
    cores: usize,
    last: Option<Instant>,
    /// Process CPU time at the previous reading.
    cpu_time: Option<Duration>,
}

impl ProcessProbe {
    pub fn new(pid: u32) -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        let cores = sys.cpus().len().max(1);
        Self { sys, pid: Pid::from_u32(pid), cores, last: None, cpu_time: None }
    }

    pub fn cores(&self) -> usize {
        self.cores
    }

    /// Reading since the previous call (the first call only primes the counters).
    pub fn sample(&mut self) -> Option<(ProcessReading, SystemSample)> {
        let kind = ProcessRefreshKind::nothing().with_cpu().with_memory().with_disk_usage();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[self.pid]), true, kind);
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        let now = Instant::now();
        let used = cpu_time(self.pid.as_u32());
        let before = std::mem::replace(&mut self.cpu_time, used);
        let dt = self.last.replace(now).map(|t| now.duration_since(t).as_secs_f64())?;
        let p = self.sys.process(self.pid)?;
        let cpu = match (used, before) {
            (Some(now), Some(before)) if dt > 0.0 => (now.saturating_sub(before).as_secs_f64() / dt / self.cores as f64 * 100.0) as f32,
            _ => p.cpu_usage() / self.cores as f32,
        };
        let io = p.disk_usage();
        let per_sec = |bytes: u64| if dt > 0.0 { bytes as f64 / dt } else { 0.0 };
        let process = ProcessReading {
            cpu: cpu.clamp(0.0, 100.0),
            working_set: p.memory(),
            private_bytes: p.virtual_memory(),
            read_per_sec: per_sec(io.read_bytes),
            write_per_sec: per_sec(io.written_bytes),
            threads: thread_count(self.pid.as_u32()),
        };
        let system = SystemSample {
            cpu: self.sys.global_cpu_usage().clamp(0.0, 100.0),
            free_ram: self.sys.available_memory(),
            total_ram: self.sys.total_memory(),
        };
        Some((process, system))
    }

    /// Forget the previous reading (after an idle period, so rates do not average over it).
    pub fn reset(&mut self) {
        self.last = None;
        self.cpu_time = None;
    }
}

/// Is `pid` a live Strata process (GUI or CLI)?
pub fn is_strata_process(pid: u32) -> bool {
    let mut sys = System::new();
    let pid = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).is_some_and(|p| p.name().to_string_lossy().to_ascii_lowercase().contains("strata"))
}

#[cfg(windows)]
fn thread_count(pid: u32) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    // SAFETY: snapshot handle checked before use and closed once; the entry is a live local
    // with its size field set as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return None;
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut n = 0;
        let mut ok = Thread32First(snap, &mut entry);
        while ok != 0 {
            n += u32::from(entry.th32OwnerProcessID == pid);
            ok = Thread32Next(snap, &mut entry);
        }
        CloseHandle(snap);
        Some(n)
    }
}

#[cfg(not(windows))]
fn thread_count(_pid: u32) -> Option<u32> {
    None
}

/// Kernel + user time of a process so far.
#[cfg(windows)]
fn cpu_time(pid: u32) -> Option<Duration> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    // SAFETY: the handle is checked before use and closed once; out-pointers are live locals.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(handle);
        (ok != 0).then(|| Duration::from_nanos((ticks(kernel) + ticks(user)).saturating_mul(100)))
    }
}

#[cfg(not(windows))]
fn cpu_time(_pid: u32) -> Option<Duration> {
    None
}
