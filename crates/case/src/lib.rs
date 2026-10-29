//! Case context: the aggregate root that owns all evidence of one investigation.
//!
//! A case is a folder `<name>.strata/` holding `case.db` (SQLite) and caches. Several disks
//! can be added; findings from all of them live in one store so correlation can show where
//! disks complement each other.

mod attribution;
mod balances;
mod case;
mod correlation;
mod schema;
mod store;

pub use attribution::{Attribution, EvidenceLayout, FileRef};
pub use case::{Case, EvidenceRecord};
pub use correlation::{CorrelationService, FileComplement, SameMedium, SharedFinding};
pub use store::{HitQuery, StoredHit};
