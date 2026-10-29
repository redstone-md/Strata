//! CPU time of the threads working for one job.
//!
//! Every thread that starts working for a job registers itself (scanner workers through the
//! engine's thread hook, the step thread directly). On Windows the set keeps a handle per
//! thread and reads its kernel + user time with `GetThreadTimes`, so threads that already
//! exited still count. Elsewhere per-thread times are not read and the monitor falls back to
//! the process's CPU share.

use parking_lot::Mutex;
use std::time::Duration;

#[derive(Default)]
pub struct ThreadSet {
    inner: Mutex<platform::Threads>,
}

impl ThreadSet {
    /// Start counting the calling thread's CPU time for this job.
    pub fn register_current(&self) {
        self.inner.lock().register_current();
    }

    /// Stop counting the calling thread (it moves on to other work).
    pub fn release_current(&self) {
        self.inner.lock().release_current();
    }

    /// CPU time spent for the job so far; `None` where per-thread times are unavailable.
    pub fn cpu_time(&self) -> Option<Duration> {
        self.inner.lock().cpu_time()
    }
}

#[cfg(windows)]
mod platform {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetCurrentThreadId, GetExitCodeThread, GetThreadTimes, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
    };

    struct Tracked {
        tid: u32,
        handle: Handle,
        /// CPU time the thread had used before it joined the job.
        base: Duration,
    }

    /// An owned thread handle, closed on drop.
    struct Handle(HANDLE);

    // SAFETY: a thread handle is a kernel object reference usable from any thread.
    unsafe impl Send for Handle {}

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenThread and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    impl Handle {
        fn cpu(&self) -> Option<Duration> {
            let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
            // SAFETY: valid handle with query rights; all out-pointers are live locals.
            let ok = unsafe { GetThreadTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) };
            let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
            (ok != 0).then(|| Duration::from_nanos((ticks(kernel) + ticks(user)).saturating_mul(100)))
        }

        fn exited(&self) -> bool {
            let mut code = 0u32;
            // SAFETY: valid handle; `code` is a live local.
            let ok = unsafe { GetExitCodeThread(self.0, &mut code) };
            ok != 0 && code != STILL_ACTIVE as u32
        }
    }

    #[derive(Default)]
    pub struct Threads {
        live: Vec<Tracked>,
        /// Time of threads that left the job or exited.
        finished: Duration,
    }

    impl Threads {
        pub fn register_current(&mut self) {
            // SAFETY: plain query of the calling thread's id.
            let tid = unsafe { GetCurrentThreadId() };
            if self.live.iter().any(|t| t.tid == tid) {
                return;
            }
            // SAFETY: opening our own running thread for limited queries.
            let raw = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid) };
            if raw.is_null() {
                return;
            }
            let handle = Handle(raw);
            let base = handle.cpu().unwrap_or_default();
            self.live.push(Tracked { tid, handle, base });
        }

        pub fn release_current(&mut self) {
            // SAFETY: plain query of the calling thread's id.
            let tid = unsafe { GetCurrentThreadId() };
            if let Some(i) = self.live.iter().position(|t| t.tid == tid) {
                let t = self.live.swap_remove(i);
                self.finished += t.handle.cpu().unwrap_or(t.base).saturating_sub(t.base);
            }
        }

        pub fn cpu_time(&mut self) -> Option<Duration> {
            let mut total = self.finished;
            let mut i = 0;
            while i < self.live.len() {
                let t = &self.live[i];
                let used = t.handle.cpu().unwrap_or(t.base).saturating_sub(t.base);
                if t.handle.exited() {
                    self.finished += used;
                    self.live.swap_remove(i);
                } else {
                    i += 1;
                }
                total += used;
            }
            Some(total)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::time::Duration;

    #[derive(Default)]
    pub struct Threads;

    impl Threads {
        pub fn register_current(&mut self) {}
        pub fn release_current(&mut self) {}
        pub fn cpu_time(&mut self) -> Option<Duration> {
            None
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::Instant;

    fn spin(for_: Duration) {
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed() < for_ {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
        }
    }

    #[test]
    fn counts_registered_threads_including_exited_ones_only() {
        let set = std::sync::Arc::new(ThreadSet::default());
        spin(Duration::from_millis(60)); // before registering: not counted
        std::thread::scope(|s| {
            for _ in 0..2 {
                let set = set.clone();
                s.spawn(move || {
                    set.register_current();
                    spin(Duration::from_millis(80));
                });
            }
        });
        let used = set.cpu_time().unwrap();
        assert!(used >= Duration::from_millis(100), "two exited workers counted: {used:?}");
        assert!(used < Duration::from_millis(400), "{used:?}");
        set.register_current();
        set.release_current();
        assert!(set.cpu_time().unwrap() < Duration::from_millis(400), "this thread's earlier spin is not counted");
    }
}
