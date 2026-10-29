//! Scan engine: reads a source sequentially exactly once and fans every chunk out to all
//! registered detectors (and chunk observers, such as the disk index profiler) on a worker pool.
//!
//! Sequential reading matters: evidence often lives on slow or failing spinning disks.

mod control;
mod observer;
mod priority;
mod scanner;

pub use control::{ScanControl, ScanSnapshot};
pub use observer::ChunkObserver;
pub use scanner::{ScanSummary, Scanner};
