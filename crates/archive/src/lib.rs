//! `archive` bounded context: what is inside archives found on evidence.
//!
//! - [`ArchiveReader`]: one archive's member list and member bytes, damage-tolerant, for
//!   ZIP/ZIP64 (incl. traditional and AES encryption with user-supplied passwords), GZIP,
//!   BZIP2, XZ, TAR, 7z, RAR4/RAR5 and CAB. [`open_archive`] picks the reader.
//! - [`Unpacker`]: recursive walk (zip in rar in 7z...) under [`UnpackLimits`], handing every
//!   member to a visitor with its virtual path `outer.zip!/dir/inner.rar!/file.txt`.
//!
//! Archive bytes are hostile: third-party decoders run behind a panic guard and every failure
//! becomes [`Damage`](strata_kernel::Damage) on the member, never a crash.

mod codec;
mod entry;
mod external;
pub(crate) mod formats;
mod reader;
mod unpack;

pub use entry::{ArchiveEntry, ArchiveFormat};
pub use external::SevenZipTool;
pub use reader::{ArchiveReader, MemberData, OpenOptions, open_archive, open_archive_with};
pub use unpack::{Member, UnpackLimits, UnpackReport, Unpacker};

#[cfg(test)]
mod tests;
