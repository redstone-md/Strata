//! Evidence acquisition context: everything that turns a medium into addressable bytes.
//!
//! All sources are read-only and implement [`BlockSource`]. Unreadable areas read back as
//! zeros and are reported through [`BlockSource::damage`].

mod block;
mod composite;
mod file_io;
mod open;
mod physical;
mod raw;
mod rdr;
mod slice;

pub use block::{BlockSource, SourceInfo, SourceKind};
pub use composite::CompositeSource;
pub use open::open_source;
pub use physical::PhysicalDrive;
pub use raw::RawImage;
pub use rdr::RdrImage;
pub use slice::SliceSource;
