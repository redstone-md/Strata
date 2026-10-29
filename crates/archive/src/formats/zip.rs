//! ZIP/ZIP64 over identify's tolerant [`ZipArchive`]: central directory or local-header
//! rebuild, per-member damage, extra methods (bzip2, LZMA, XZ) and password decryption.

use super::zip_crypto::{self, Plain};
use crate::codec::{self, Decoded};
use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use strata_identify::{Extracted, ZipArchive, ZipEntry};
use strata_kernel::{ByteRange, Damage, Error, Result, Timestamp};

pub(crate) struct ZipReader<'a> {
    data: &'a [u8],
    zip: ZipArchive,
    passwords: Vec<String>,
}

impl<'a> ZipReader<'a> {
    pub fn open(data: &'a [u8], passwords: Vec<String>) -> Option<Self> {
        let zip = ZipArchive::parse(data);
        (!zip.entries().is_empty()).then_some(Self { data, zip, passwords })
    }

    fn entry(&self, e: &ArchiveEntry) -> Result<&ZipEntry> {
        self.zip.entries().get(e.index).ok_or_else(|| Error::Other(format!("{}: no such member", e.path)))
    }

    /// Raw (still compressed, maybe encrypted) member bytes, with truncation noted.
    fn raw(&self, e: &ZipEntry) -> Result<(&'a [u8], Vec<Damage>)> {
        let start = e.data_start.ok_or_else(|| Error::Other(format!("{}: local header missing", e.name)))?;
        let declared = usize::try_from(e.compressed_size).unwrap_or(usize::MAX);
        let available = self.data.len().saturating_sub(start);
        let mut damage = Vec::new();
        if declared > available {
            damage.push(Damage::new(
                strata_kernel::DamageKind::Truncated,
                Some(ByteRange::new(start as u64, e.compressed_size)),
                format!("{}: data truncated ({available} of {declared} bytes present)", e.name),
            ));
        }
        Ok((self.data.get(start..start + declared.min(available)).unwrap_or_default(), damage))
    }

    /// Decompress `input` stored with `method`.
    fn decode(method: u16, input: &[u8], size: u64, limit: usize) -> Result<Decoded> {
        if let Some(x) = Extracted::decode(method, input, limit) {
            return Ok(Decoded { complete: x.complete, data: x.data, damage: x.damage });
        }
        Ok(match method {
            12 => codec::bzip2(input, limit),
            14 => codec::zip_lzma(input, size, limit),
            95 => codec::xz(input, limit),
            m => return Err(Error::Other(format!("compression method {m} not supported"))),
        })
    }

    fn crc_check(e: &ZipEntry, out: &mut Decoded) {
        if out.complete && out.data.len() as u64 == e.uncompressed_size && crc32fast::hash(&out.data) != e.crc32 {
            out.damage.push(Damage::corrupt(ByteRange::new(e.data_start.unwrap_or(0) as u64, e.compressed_size), format!("{}: CRC mismatch", e.name)));
        }
    }

    fn read_encrypted(&self, e: &ZipEntry, limit: usize) -> Result<MemberData> {
        let (raw, mut damage) = self.raw(e)?;
        let mut last_err = None;
        for (i, pw) in self.passwords.iter().enumerate() {
            let Some(Plain { data, method, crc_checked }) = zip_crypto::decrypt(self.data, e, raw, pw) else { continue };
            let mut out = match Self::decode(method, &data, e.uncompressed_size, limit) {
                Ok(out) => out,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };
            // Traditional encryption has a 1-byte check: a wrong password can pass it, the CRC
            // tells. AES members are authenticated; AE-2 carries no CRC at all.
            let crc_bad = crc_checked && out.complete && crc32fast::hash(&out.data) != e.crc32;
            if crc_bad && i + 1 < self.passwords.len() {
                continue;
            }
            if crc_bad {
                Self::crc_check(e, &mut out);
            }
            damage.append(&mut out.damage);
            return Ok((out.data, damage));
        }
        Err(last_err.unwrap_or_else(|| Error::Other(format!("{}: encrypted, no password from the list fits", e.name))))
    }
}

impl ArchiveReader for ZipReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Zip
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        self.zip
            .entries()
            .iter()
            .enumerate()
            .map(|(i, z)| {
                let mut e = ArchiveEntry::new(i, &z.name);
                e.size = Some(z.uncompressed_size);
                e.packed = Some(z.compressed_size);
                e.encrypted = z.is_encrypted();
                e.is_dir = z.is_dir();
                e.mtime = Timestamp::from_dos((z.dos_time >> 16) as u16, z.dos_time as u16);
                e.damage = z.damage.clone();
                e
            })
            .collect()
    }

    fn damage(&self) -> Vec<Damage> {
        self.zip.damage().to_vec()
    }

    fn can_decrypt(&self) -> bool {
        !self.passwords.is_empty()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        let e = self.entry(entry)?;
        if e.is_encrypted() {
            return self.read_encrypted(e, limit);
        }
        if matches!(e.method, 0 | 8) {
            let x = self.zip.extract(self.data, e, limit);
            if x.data.is_empty() && !x.damage.is_empty() && e.uncompressed_size > 0 {
                return Err(Error::Other(x.damage.iter().map(|d| d.note()).collect::<Vec<_>>().join("; ")));
            }
            return Ok((x.data, x.damage));
        }
        let (raw, mut damage) = self.raw(e)?;
        let mut out = Self::decode(e.method, raw, e.uncompressed_size, limit)?;
        Self::crc_check(e, &mut out);
        damage.append(&mut out.damage);
        Ok((out.data, damage))
    }
}
