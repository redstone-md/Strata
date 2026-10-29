//! 7z via the pure-Rust `sevenz-rust2` decoder, one block at a time so a bad or encrypted
//! block costs only its own members.

use crate::codec::{guarded, read_limited};
use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use sevenz_rust2::{Archive, BlockDecoder, EncoderMethod, Password};
use std::io::{Cursor, Read};
use std::ops::ControlFlow;
use strata_kernel::{Damage, DamageKind, Error, Result, Timestamp};

/// Members declaring more than this are not drained to reach the next member of a solid block.
const MAX_DRAIN: u64 = 16 << 30;

pub(crate) struct SevenZipReader<'a> {
    data: &'a [u8],
    archive: Option<Archive>,
    damage: Vec<Damage>,
}

impl<'a> SevenZipReader<'a> {
    pub fn open(data: &'a [u8]) -> Self {
        let parsed = guarded("7z header", || Archive::read(&mut Cursor::new(data), &Password::empty()));
        let (archive, damage) = match parsed {
            Ok(Ok(a)) => (Some(a), Vec::new()),
            Ok(Err(sevenz_rust2::Error::PasswordRequired)) => {
                (None, vec![Damage::new(DamageKind::Missing, None, "7z: file list is encrypted (password required)")])
            }
            Ok(Err(e)) => (None, vec![Damage::new(DamageKind::Corrupt, None, format!("7z header: {e}"))]),
            Err(e) => (None, vec![Damage::new(DamageKind::Corrupt, None, e.to_string())]),
        };
        Self { data, archive, damage }
    }

    fn block_encrypted(archive: &Archive, block: usize) -> bool {
        archive
            .blocks
            .get(block)
            .is_some_and(|b| b.coders.iter().any(|c| c.encoder_method_id() == EncoderMethod::ID_AES256_SHA256))
    }

    fn file_block(archive: &Archive, file: usize) -> Option<usize> {
        archive.stream_map.file_block_index.get(file).copied().flatten()
    }

    /// Decode `block`, calling `each(file index, reader)` for its members.
    fn decode_block(
        &self,
        archive: &Archive,
        block: usize,
        each: &mut dyn FnMut(usize, &mut dyn Read) -> ControlFlow<()>,
    ) -> std::result::Result<ControlFlow<()>, String> {
        let base = archive.files.as_ptr() as usize;
        let size = std::mem::size_of::<sevenz_rust2::ArchiveEntry>().max(1);
        let mut source = Cursor::new(self.data);
        let password = Password::empty();
        let mut flow = ControlFlow::Continue(());
        let run = guarded("7z block", || {
            BlockDecoder::new(1, block, archive, &password, &mut source).for_each_entries(&mut |f, r| {
                let index = (f as *const _ as usize).wrapping_sub(base) / size;
                flow = each(index, r);
                Ok(flow.is_continue())
            })
        });
        match run {
            Ok(Ok(_)) => Ok(flow),
            Ok(Err(e)) => Err(format!("7z block {block}: {e}")),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Read one member's data from `r`, then drain the rest so the next member lines up.
    fn take(r: &mut dyn Read, declared: u64, limit: usize, name: &str) -> MemberData {
        let out = read_limited(&mut *r, limit, name);
        if !out.complete && declared <= MAX_DRAIN {
            let _ = std::io::copy(r, &mut std::io::sink());
        }
        out.into_parts()
    }
}

impl ArchiveReader for SevenZipReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::SevenZip
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        let Some(a) = &self.archive else { return Vec::new() };
        a.files
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.is_anti_item)
            .map(|(i, f)| {
                let mut e = ArchiveEntry::new(i, &f.name);
                e.size = Some(f.size);
                e.packed = (f.compressed_size > 0).then_some(f.compressed_size);
                e.is_dir = f.is_directory;
                e.encrypted = Self::file_block(a, i).is_some_and(|b| Self::block_encrypted(a, b));
                e.mtime = f.has_last_modified_date.then(|| Timestamp::from_filetime(u64::from(f.last_modified_date))).flatten();
                e
            })
            .collect()
    }

    fn damage(&self) -> Vec<Damage> {
        self.damage.clone()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        let a = self.archive.as_ref().ok_or_else(|| Error::Other("7z: no readable file list".into()))?;
        let Some(block) = Self::file_block(a, entry.index) else { return Ok((Vec::new(), Vec::new())) };
        if Self::block_encrypted(a, block) {
            return Err(Error::Other("encrypted".into()));
        }
        let mut found = None;
        let declared = entry.size.unwrap_or(0);
        let _flow = self.decode_block(a, block, &mut |i, r| {
            if i == entry.index {
                found = Some(Self::take(r, declared, limit, &entry.path));
                return ControlFlow::Break(());
            }
            let _ = std::io::copy(r, &mut std::io::sink());
            ControlFlow::Continue(())
        })
        .map_err(Error::Other)?;
        found.ok_or_else(|| Error::Other(format!("{}: not reached in its block", entry.path)))
    }

    fn read_all(
        &self,
        limit: &dyn Fn(&ArchiveEntry) -> usize,
        each: &mut dyn FnMut(&ArchiveEntry, Result<MemberData>) -> ControlFlow<()>,
    ) {
        let Some(a) = &self.archive else { return };
        let entries = self.entries();
        let by_index = |i: usize| entries.iter().find(|e| e.index == i);
        for block in 0..a.blocks.len() {
            let members: Vec<&ArchiveEntry> =
                entries.iter().filter(|e| !e.is_dir && Self::file_block(a, e.index) == Some(block)).collect();
            if Self::block_encrypted(a, block) {
                for e in members {
                    if each(e, Err(Error::Other("encrypted".into()))).is_break() {
                        return;
                    }
                }
                continue;
            }
            let mut seen = Vec::new();
            let run = self.decode_block(a, block, &mut |i, r| {
                let Some(e) = by_index(i).filter(|e| !e.is_dir) else {
                    let _ = std::io::copy(r, &mut std::io::sink());
                    return ControlFlow::Continue(());
                };
                seen.push(i);
                let data = Self::take(r, e.size.unwrap_or(0), limit(e), &e.path);
                each(e, Ok(data))
            });
            match run {
                Ok(ControlFlow::Break(())) => return,
                Ok(_) => {}
                Err(msg) => {
                    for e in members.into_iter().filter(|e| !seen.contains(&e.index)) {
                        if each(e, Err(Error::Other(msg.clone()))).is_break() {
                            return;
                        }
                    }
                }
            }
        }
        // Members without data (empty files).
        for e in entries.iter().filter(|e| !e.is_dir && Self::file_block(a, e.index).is_none()) {
            if each(e, Ok((Vec::new(), Vec::new()))).is_break() {
                return;
            }
        }
    }
}
