//! Scan engine: reads a source sequentially exactly once and fans every chunk out to all
//! registered detectors on a worker pool.
//!
//! Sequential reading matters: evidence often lives on slow or failing spinning disks.

mod control;
mod priority;
mod scanner;

pub use control::{ScanControl, ScanSnapshot};
pub use scanner::{ScanSummary, Scanner};
