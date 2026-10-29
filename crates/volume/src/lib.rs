//! Volume context: where filesystems live on a disk.
//!
//! [`VolumeScanner`] reads MBR (with extended chains) and GPT, then sweeps for boot sectors (and ext superblocks) that
//! no table references (deleted or lost partitions). An image of a single partition is detected
//! as one volume starting at 0.

mod boot;
mod mbr;
mod gpt;
mod scanner;

pub use boot::{BootSector, FsKind};
pub use scanner::{Volume, VolumeOrigin, VolumeScanner};
