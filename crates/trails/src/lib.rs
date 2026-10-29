//! Trails context — where did the wallet go?
//!
//! A wallet file leaves traces long after it is gone: a shortcut to it, a recent-documents
//! entry, the Prefetch list of the wallet program that loaded it, a download, a Recycle Bin
//! record, its deleted entry in the file table, a copy in a backup folder or an archive, a
//! mail attachment, or its pages in free space. [`TrailBuilder`] links every such sighting
//! across all disks of a case into one [`Trail`] per file: a dated chain of evidence, a
//! [`Verdict`] on its fate (live, moved, deleted, archived, mailed, carved, not found) with a
//! confidence and plain sentences, and hints where to look when it was not found.

mod builder;
mod cluster;
mod fate;
mod hints;
mod inputs;
mod path_key;
mod steps;
mod traces;
mod trail;

pub use builder::TrailBuilder;
pub use inputs::{ArchiveMember, EntryState, FileRecord, MailAttachment, TrailInputs, WalletHit};
pub use steps::describe as describe_step;
pub use trail::{Fate, StepKind, StepLink, Trail, TrailStep, Verdict};

#[cfg(test)]
mod tests;
