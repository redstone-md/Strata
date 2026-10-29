//! Case context: the aggregate root that owns all evidence of one investigation.
//!
//! A case is a folder `<name>.strata/` holding `case.db` (SQLite) and caches. Several disks
//! can be added; findings from all of them live in one store so correlation can show where
//! disks complement each other.

mod activity;
mod archives;
mod attribution;
mod balances;
mod case;
mod connections;
mod correlation;
mod jobs;
mod file_rows;
mod insights;
mod layout_ranges;
mod messages;
mod pool;
mod recheck;
mod recovered;
mod repeats;
mod schema;
mod search_store;
mod store;
mod system_paths;
mod timeline;
mod writer;

pub use activity::{EventFilter, FactGroup, HourlyEvents, TitledEvents};
pub use archives::ArchiveMemberRow;
pub use attribution::{Attribution, EvidenceLayout, FileRef};
pub use case::{Case, EvidenceRecord, SAVE_EVERY, ScanCommit};
pub use jobs::{JobRecord, JobStamp};
pub use writer::CaseWriter;
pub use file_rows::{FileRow, FileTypes, TypeCount};
pub use messages::{FoundMessage, MessageLocation, MessageQuery, MessageRow, MessageState, StoredBatch, StoredMessage};
pub use recheck::{RecheckRow, Verdict};
pub use system_paths::is_system_path;
pub use recovered::DELETED_PARTITION;
pub use search_store::{SearchRecord, SearchResultRow};
pub use correlation::{CorrelationService, FileComplement, SameMedium, SharedFinding};
pub use store::{HitQuery, StoredHit};
pub use timeline::{EventQuery, HostFact};
