//! The reader contract and format dispatch.

use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::external::SevenZipTool;
use crate::formats;
use std::ops::ControlFlow;
use std::path::PathBuf;
use strata_identify::{Identifier, TypeId};
use strata_kernel::{Damage, Result};

/// A member's recovered bytes plus what went wrong while producing them.
pub type MemberData = (Vec<u8>, Vec<Damage>);

/// One opened archive. Implementations never panic on malformed input.
pub trait ArchiveReader {
    fn format(&self) -> ArchiveFormat;

    /// Every member the archive lists (or that could be rebuilt from damaged structures).
    fn entries(&self) -> Vec<ArchiveEntry>;

    /// Bytes of one member, at most `limit`. `Err` means nothing could be recovered
    /// (encrypted without a matching password, unsupported method...).
    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData>;

    /// Archive-level damage (header problems, encrypted directory...).
    fn damage(&self) -> Vec<Damage> {
        Vec::new()
    }

    /// Read every file member in archive order; `limit` is asked per member. Solid formats
    /// override this to decode in one pass.
    fn read_all(
        &self,
        limit: &dyn Fn(&ArchiveEntry) -> usize,
        each: &mut dyn FnMut(&ArchiveEntry, Result<MemberData>) -> ControlFlow<()>,
    ) {
        for e in self.entries().into_iter().filter(|e| !e.is_dir) {
            let data = if e.encrypted && !self.can_decrypt() {
                Err(strata_kernel::Error::Other("encrypted".into()))
            } else {
                self.read(&e, limit(&e))
            };
            if each(&e, data).is_break() {
                return;
            }
        }
    }

    /// Whether encrypted members are worth a [`ArchiveReader::read`] attempt.
    fn can_decrypt(&self) -> bool {
        false
    }
}

/// How archives are opened.
#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    /// Passwords of the user's own archives, tried on encrypted ZIP members (traditional
    /// PKWARE and WinZip AES). Nothing is generated or brute-forced.
    pub passwords: Vec<String>,
    /// Folder for temporary copies some decoders need (RAR); defaults to the system temp
    /// folder. Evidence is never written: only copies of archive bytes land here.
    pub scratch: Option<PathBuf>,
    /// External 7-Zip, used for RAR when the built-in reader cannot open it.
    pub external: Option<SevenZipTool>,
}

/// Open `bytes` with the default options. `hint` skips identification when the type is known.
pub fn open_archive<'a>(bytes: &'a [u8], hint: Option<TypeId>) -> Option<Box<dyn ArchiveReader + 'a>> {
    open_archive_with(bytes, hint, &OpenOptions::default())
}

/// Bytes identified for dispatch; enough for every archive header and the TAR magic.
const HEAD: usize = 64 * 1024;

pub fn open_archive_with<'a>(bytes: &'a [u8], hint: Option<TypeId>, options: &OpenOptions) -> Option<Box<dyn ArchiveReader + 'a>> {
    let t = hint.unwrap_or_else(|| Identifier::new().identify(&bytes[..bytes.len().min(HEAD)], None).file_type);
    let format = ArchiveFormat::for_type(t)?;
    formats::open(format, bytes, options)
}

impl OpenOptions {
    pub(crate) fn scratch_dir(&self) -> PathBuf {
        self.scratch.clone().unwrap_or_else(|| std::env::temp_dir().join("strata-archive"))
    }
}
