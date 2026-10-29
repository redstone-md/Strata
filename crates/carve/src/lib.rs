//! `carve` bounded context: recover files from raw evidence (typically unallocated space)
//! using the identify registry's signatures, size information and validators.

mod boundary;
mod carver;
mod ranges;
mod view;

pub use boundary::Boundary;
pub use carver::{CarveOptions, CarvedFile, Carver, LengthSource};
pub use ranges::carve_ranges;
pub use view::SourceView;
