//! Case context: the aggregate root that owns all evidence of one investigation.
//!
//! A case is a folder `<name>.strata/` holding `case.db` (SQLite) and caches. Several disks
//! can be added; findings from all of them live in one store so correlation can show where
//! disks complement each other.

mod archives;
mod attribution;
mod balances;
mod case;
mod correlation;
mod insights;
mod schema;
mod store;
mod timeline;

pub use archives::ArchiveMemberRow;
pub use attribution::{Attribution, EvidenceLayout, FileRef};
pub use case::{Case, EvidenceRecord};
pub use correlation::{CorrelationService, FileComplement, SameMedium, SharedFinding};
pub use store::{HitQuery, StoredHit};
pub use timeline::{EventQuery, HostFact};
