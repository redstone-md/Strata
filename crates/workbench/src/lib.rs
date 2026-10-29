//! Application layer. GUI and CLI talk to Strata only through [`Workbench`].

mod catalog;
mod jobs;
mod monitor;
mod sector_map;
mod steps;
mod triage;
mod workbench;

pub use catalog::DetectorCatalog;
pub use jobs::context::CheckpointPolicy;
pub use jobs::{CheckpointInfo, Job, JobId, JobKind, JobState, JobView, LogLine, ProgressUnit, eta};
pub use monitor::{JobSample, Monitor, MonitorView, ProcessWatch, ResourceSample, SystemSample};
pub use steps::ArchiveSummary;
pub use sector_map::{SectorCell, SectorMap};
pub use workbench::Workbench;

pub use strata_case::{EventQuery, HostFact, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
pub use strata_kernel::scan::HitCategory;
pub use strata_timeline::{EventKind, TimelineEvent};
pub use strata_chain::AddressBalance;
pub use strata_kernel::{EvidenceId, Timestamp};
