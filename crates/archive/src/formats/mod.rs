//! One reader per archive format.

mod cab;
mod rar;
mod sevenz;
mod stream;
mod tar;
mod zip;
pub(crate) mod zip_crypto;

use crate::entry::ArchiveFormat;
use crate::reader::{ArchiveReader, OpenOptions};

pub(crate) fn open<'a>(format: ArchiveFormat, bytes: &'a [u8], options: &OpenOptions) -> Option<Box<dyn ArchiveReader + 'a>> {
    match format {
        ArchiveFormat::Zip => zip::ZipReader::open(bytes, options.passwords.clone()).map(|r| Box::new(r) as _),
        ArchiveFormat::Gzip | ArchiveFormat::Bzip2 | ArchiveFormat::Xz => Some(Box::new(stream::StreamReader::new(format, bytes))),
        ArchiveFormat::Tar => tar::TarReader::open(bytes).map(|r| Box::new(r) as _),
        ArchiveFormat::SevenZip => Some(Box::new(sevenz::SevenZipReader::open(bytes))),
        ArchiveFormat::Rar => rar::open(bytes, options),
        ArchiveFormat::Cab => cab::open(bytes, options),
    }
}
