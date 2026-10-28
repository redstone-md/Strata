//! Shared kernel used by every Strata bounded context.

pub mod bytes;
mod confidence;
mod damage;
mod error;
mod ids;
mod range;
pub mod scan;
pub mod time;

pub use confidence::Confidence;
pub use damage::{Damage, DamageKind};
pub use error::{Error, Result};
pub use ids::{EvidenceId, VolumeId};
pub use range::ByteRange;
pub use time::Timestamp;
