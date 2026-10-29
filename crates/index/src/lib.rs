//! `index` bounded context: a light, fast map of what lies where on a disk.
//!
//! - [`DiskIndex`]: one packed [`BlockRecord`] per fixed-size block (content class, text
//!   encoding, entropy, ownership and flags) plus side tables of file-signature hits and
//!   recognised boot records. Queries return coalesced byte ranges.
//! - [`IndexBuilder`]: fills an index during the single scan pass as a
//!   [`strata_engine::ChunkObserver`], so building it costs no extra read.
//! - [`IndexFile`]: versioned, checksummed on-disk form, saved incrementally with the scan
//!   watermark.
//! - [`scn`]: reader for R-Studio scan files (`.scn`), which seed an index before our own pass.

mod builder;
mod classify;
mod file;
mod index;
mod query;
mod record;
pub mod scn;
mod side;

pub use builder::IndexBuilder;
pub use classify::Classifier;
pub use file::IndexFile;
pub use index::{DEFAULT_BLOCK_SIZE, DiskIndex, Provenance};
pub use query::{CellContent, IndexStats};
pub use record::{BlockClass, BlockRecord, Ownership, TextKind};
pub use side::{BootRecord, EntrySource, SignatureHit};
