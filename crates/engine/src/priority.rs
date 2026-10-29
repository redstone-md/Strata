//! Scan workers run below normal priority so the desktop and the app's UI stay responsive
//! while a long scan saturates its threads.

#[cfg(windows)]
pub fn lower_current_thread() {
    use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL};
    // SAFETY: pseudo-handle of the calling thread; failure only leaves normal priority.
    unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    }
}

#[cfg(not(windows))]
pub fn lower_current_thread() {}
