//! Volume context: where filesystems live on a disk.
//!
//! [`VolumeScanner`] reads MBR (with extended chains) and GPT, then sweeps likely offsets for
//! boot sectors, ext superblocks and NTFS backup boot sectors that no table references
//! (deleted or lost partitions). An image of a single partition is detected as one volume
//! starting at 0. [`PartitionDetector`] does the exhaustive version of that search inside the
//! deep scan, and [`CandidateResolver`] turns its findings into believable volumes.

mod boot;
mod candidate;
mod crc32;
mod detector;
mod gpt;
mod mbr;
mod probe;
mod scanner;
mod sweep;

pub use boot::{BootSector, FsKind};
pub use candidate::{CandidateResolver, Evidence, VolumeCandidate};
pub use detector::PartitionDetector;
pub use gpt::candidates as gpt_candidates;
pub use probe::GptHeader;
pub use scanner::{Volume, VolumeOrigin, VolumeScanner};
