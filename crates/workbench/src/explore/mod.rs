//! Exploring a disk beyond findings: deleted partitions, content search over any range,
//! file browsing with deleted and orphaned entries, and recovery to a folder.

mod facade;
mod files;
mod partitions;
pub mod recovery;
mod search_job;

pub use files::{DirNode, FileFilter, FileListQuery, FileListing, FileView, type_category};
pub use partitions::{PartitionRecovery, PartitionReport};
pub use search_job::{DiskSearch, MAX_RESULTS, location};
