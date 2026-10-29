//! Application layer. GUI and CLI talk to Strata only through [`Workbench`].

mod catalog;
mod jobs;
mod workbench;

pub use catalog::DetectorCatalog;
pub use jobs::{Job, JobId, JobKind, JobState, JobView};
pub use workbench::Workbench;

pub use strata_case::{CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
pub use strata_kernel::scan::HitCategory;
pub use strata_kernel::{EvidenceId, Timestamp};
