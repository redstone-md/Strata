//! The file type registry: every known type is one row of [`table::TYPES`].

mod table;

use crate::probe::Probe;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Broad family of a file type, used for extension-mismatch reasoning and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Archive,
    Document,
    Image,
    Executable,
    Database,
    Wallet,
    Credentials,
    Mail,
    Registry,
    Browser,
    Text,
    Media,
    System,
    Encrypted,
    Unknown,
}

impl Category {
    /// Categories whose content is valuable enough that hiding it under a foreign extension is
    /// suspicious (somebody tried to make it look boring).
    pub fn is_valuable(self) -> bool {
        matches!(
            self,
            Category::Archive
                | Category::Wallet
                | Category::Credentials
                | Category::Database
                | Category::Mail
                | Category::Encrypted
                | Category::Document
        )
    }
}

macro_rules! type_ids {
    ($($variant:ident),* $(,)?) => {
        /// Stable identifier of a file type. Serialized as the registry key (`zip`, `docx`...).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum TypeId { $($variant),* }

        impl TypeId {
            pub const ALL: &'static [TypeId] = &[$(TypeId::$variant),*];
        }
    };
}

type_ids!(
    Zip, Docx, Xlsx, Pptx, Jar, Apk, Odt, Ods, Odp, Epub, SevenZip, Rar4, Rar5, Cab, Gzip, Bzip2,
    Xz, Tar, Iso9660, Pdf, Ole2, Doc, Xls, Ppt, Msg, ThumbsDb, Rtf, Pe, Exe, Dll, Sys, Elf, Jpeg,
    Png, Gif, Bmp, Tiff, Webp, Ico, Mp3, Wav, Avi, Mp4, Mov, Mkv, Flv, Sqlite, BerkeleyDb,
    BitcoinCoreBdb, BitcoinCoreSqlite, RegistryHive, Evt, Evtx, Lnk, Prefetch, PrefetchCompressed,
    NtfsMft, IeIndexDat, Pst, Dbx, Mbox, Eml, Html, Xml, Json, ElectrumWallet, ElectrumEncrypted,
    Text, KeePass1, KeePass2, EncryptedOrRandom, Unknown,
);

impl TypeId {
    pub fn spec(self) -> &'static FileType {
        Registry::get(self)
    }

    pub fn key(self) -> &'static str {
        self.spec().key
    }

    pub fn from_key(key: &str) -> Option<TypeId> {
        Registry::all().iter().find(|t| t.key == key).map(|t| t.id)
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

impl Serialize for TypeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.key())
    }
}

impl<'de> Deserialize<'de> for TypeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let key = String::deserialize(d)?;
        Ok(TypeId::from_key(&key).unwrap_or(TypeId::Unknown))
    }
}

/// A byte pattern expected at a fixed offset from the start of the file.
#[derive(Debug, Clone, Copy)]
pub struct Magic {
    pub offset: usize,
    pub bytes: &'static [u8],
}

impl Magic {
    pub const fn at(offset: usize, bytes: &'static [u8]) -> Self {
        Self { offset, bytes }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        self.offset
            .checked_add(self.bytes.len())
            .and_then(|end| data.get(self.offset..end))
            .is_some_and(|window| window == self.bytes)
    }

    /// End of the pattern relative to the file start.
    pub fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }

    /// Too short to trust without running the structural validator.
    pub fn is_weak(&self) -> bool {
        self.bytes.len() < 4
    }
}

/// Structural validator: bytes of a (possibly truncated or damaged) file starting at its header.
/// Returns `None` when the header is not this type at all.
pub type Validator = fn(&[u8]) -> Option<Probe>;

/// One row of the registry.
#[derive(Debug)]
pub struct FileType {
    pub id: TypeId,
    pub key: &'static str,
    pub name: &'static str,
    pub category: Category,
    /// Canonical extensions, lower case, without dot. `""` means "no extension is normal".
    pub extensions: &'static [&'static str],
    pub magics: &'static [Magic],
    pub footer: Option<&'static [u8]>,
    pub validator: Option<Validator>,
    /// More generic container this type is a specialisation of (docx -> zip).
    pub parent: Option<TypeId>,
    /// Content is compressed/encoded so whole zero-filled 4 KiB blocks indicate damage.
    pub dense: bool,
    /// Carving cap in bytes.
    pub max_size: u64,
}

impl FileType {
    pub fn has_extension(&self, ext: &str) -> bool {
        self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
    }

    pub fn header_matches(&self, data: &[u8]) -> bool {
        self.magics.iter().any(|m| m.matches(data))
    }

    pub fn validate(&self, data: &[u8]) -> Option<Probe> {
        self.validator.and_then(|v| v(data))
    }

    /// Ancestors from the direct parent upwards.
    pub fn ancestors(&self) -> impl Iterator<Item = TypeId> {
        std::iter::successors(self.parent, |id| id.spec().parent)
    }

    /// `self` is `other` or one of its specialisations / generalisations.
    pub fn same_family(&self, other: TypeId) -> bool {
        self.id == other || self.ancestors().any(|a| a == other) || other.spec().ancestors().any(|a| a == self.id)
    }
}

/// Read-only access to the static type table.
pub struct Registry;

impl Registry {
    pub fn all() -> &'static [FileType] {
        table::TYPES
    }

    pub fn get(id: TypeId) -> &'static FileType {
        // The table is ordered like `TypeId`; fall back to a search if someone reorders it.
        let idx = TypeId::ALL.iter().position(|t| *t == id).unwrap_or(0);
        match table::TYPES.get(idx) {
            Some(t) if t.id == id => t,
            _ => table::TYPES.iter().find(|t| t.id == id).unwrap_or(&table::UNKNOWN),
        }
    }

    /// Types whose declared extension list contains `ext`.
    pub fn by_extension(ext: &str) -> impl Iterator<Item = &'static FileType> + '_ {
        table::TYPES.iter().filter(move |t| t.has_extension(ext))
    }

    /// Types whose header magic matches the start of `data`.
    pub fn header_candidates(data: &[u8]) -> impl Iterator<Item = &'static FileType> + '_ {
        table::TYPES.iter().filter(move |t| t.header_matches(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_covers_every_id_in_order() {
        assert_eq!(Registry::all().len(), TypeId::ALL.len());
        for (row, id) in Registry::all().iter().zip(TypeId::ALL) {
            assert_eq!(row.id, *id, "table out of order at {}", row.key);
        }
    }

    #[test]
    fn keys_are_unique_and_round_trip() {
        for t in Registry::all() {
            assert_eq!(TypeId::from_key(t.key), Some(t.id));
        }
    }

    #[test]
    fn families() {
        assert!(TypeId::Docx.spec().same_family(TypeId::Zip));
        assert!(TypeId::Zip.spec().same_family(TypeId::Docx));
        assert!(!TypeId::Jpeg.spec().same_family(TypeId::Zip));
    }
}
