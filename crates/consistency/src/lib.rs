//! Consistency context: whether what Strata extracted from a disk is plausible. An
//! [`Assessment`] weighs the file index against the volumes, install and format dates against
//! user activity, cleaning and wiping programs, and where findings lie, and says per disk
//! whether it looks normally used, little used, wiped or reinstalled, or not fully read.
//!
//! The context reads plain rows ([`DiskInputs`]) so it never depends on the case database or
//! the evidence; the application layer queries and feeds them.

mod assessment;
pub mod catalog;
mod checks;
mod inputs;
mod observation;
mod units;

pub use inputs::{
    ActiveSpan, Activity, DiskInputs, EntryState, FileTable, HistoryCount, HitPlacement, Installation, NamedFile, ProfileFolder, ProgramRow,
    ProgramTrace, Tally, VolumeInputs,
};
pub use observation::{Assessment, Figure, Observation, Severity, Signal, Verdict, VerdictKind};

/// Folders that hold one profile folder per user, relative to a volume root.
pub const PROFILE_ROOTS: &[&str] = &["Users/", "Documents and Settings/", "home/"];
/// Folder an upgrade or reinstall moves the previous Windows into.
pub const PREVIOUS_WINDOWS: &str = "Windows.old/";
/// The NTFS master file table, as the file index names it.
pub const MFT_PATH: &str = "$MFT";

#[cfg(test)]
mod tests;
