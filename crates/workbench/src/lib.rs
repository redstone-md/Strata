//! Application layer. GUI and CLI talk to Strata only through [`Workbench`].

mod archives;
mod artifacts_job;
mod carving;
mod catalog;
mod file_types;
mod insights;
mod jobs;
mod sector_map;
mod triage;
mod wallet_files;
mod workbench;

pub use archives::ArchiveSummary;
pub use catalog::DetectorCatalog;
pub use jobs::{Job, JobId, JobKind, JobState, JobView};
pub use sector_map::{SectorCell, SectorMap};
pub use workbench::Workbench;

pub use strata_case::{EventQuery, HostFact, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
pub use strata_kernel::scan::HitCategory;
pub use strata_timeline::{EventKind, TimelineEvent};
pub use strata_chain::{AddressBalance, AddressHistory};
pub use strata_accounts::{Account, AccountSource, Catalogue, IdentifierKind, ServiceEntry, ServiceKind, SourceRef, Years};
pub use strata_leads::{EventRecord, Lead, LeadRef, LeadRule};
pub use strata_kernel::{EvidenceId, Timestamp};
