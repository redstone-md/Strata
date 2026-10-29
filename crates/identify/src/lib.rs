//! `identify` bounded context: what bytes are.
//!
//! - [`Registry`]: the single file-type table (magics, extensions, footers, validators, caps).
//! - [`Identifier`]: damage-tolerant identification of one file's bytes, with
//!   extension-mismatch detection ([`TypeVerdict`]).
//! - [`SignatureDetector`]: streaming file-start detector for the scan engine.
//! - [`ZipArchive`]: tolerant ZIP reader (central directory or local-header rebuild).
//! - [`measure`]: a type's own size information, used by the carver.

mod detector;
mod evidence;
mod extension;
mod formats;
mod identifier;
mod probe;
mod profile;
mod registry;
mod text;
mod verdict;
mod view;

#[doc(hidden)]
pub mod testkit;

pub use detector::SignatureDetector;
pub use extension::extension_of;
pub use formats::deflate::{DeflateRun, measure_deflate};
pub use formats::measure::{MeasureMethod, Measured, measure};
pub use formats::zip::{EntrySource, Extracted, ZipArchive, ZipEntry};
pub use identifier::Identifier;
pub use probe::Probe;
pub use profile::{BLOCK as PROFILE_BLOCK, BlockClass, BlockProfile};
pub use registry::{Category, FileType, Magic, Registry, TypeId, Validator};
pub use text::Encoding;
pub use verdict::{ExtensionMismatch, InnerItem, InnerKind, Method, TypeVerdict};
pub use view::{Buffered, ByteView, SubView};
