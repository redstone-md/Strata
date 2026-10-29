//! Application layer. GUI and CLI talk to Strata only through [`Workbench`].

mod archives;
mod artifacts_job;
mod carving;
mod catalog;
mod disk_index;
mod file_types;
mod jobs;
mod sector_map;
mod triage;
mod wallet_files;
mod workbench;

pub use archives::ArchiveSummary;
pub use catalog::DetectorCatalog;
pub use disk_index::{DiskIndexView, ScnImport};
pub use jobs::{Job, JobId, JobKind, JobState, JobView};
pub use sector_map::{SectorCell, SectorMap};
pub use workbench::Workbench;

pub use strata_case::{EventQuery, HostFact, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
pub use strata_kernel::scan::HitCategory;
pub use strata_index::{BlockClass, CellContent, IndexStats, Ownership, TextKind};
pub use strata_timeline::{EventKind, TimelineEvent};
pub use strata_chain::AddressBalance;
pub use strata_kernel::{EvidenceId, Timestamp};
