//! RAR4/RAR5 through the bundled UnRAR library (`unrar` crate, built from source), with
//! external 7-Zip as the fallback. Both need a path, so the bytes go to a temp copy.

use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::external::{ExternalReader, TempCopy};
use crate::reader::{ArchiveReader, MemberData, OpenOptions};
use std::ops::ControlFlow;
use strata_kernel::{Damage, DamageKind, Error, Result, Timestamp};
use unrar::Archive;

// The bundled UnRAR reads its settings path from the registry; `unrar_sys` does not link the
// library that provides those calls on MSVC.
#[cfg(windows)]
#[link(name = "advapi32")]
unsafe extern "system" {}

pub(crate) fn open<'a>(bytes: &[u8], options: &OpenOptions) -> Option<Box<dyn ArchiveReader + 'a>> {
    let copy = TempCopy::write(&options.scratch_dir(), bytes, "rar").ok()?;
    let copy = match UnrarReader::open(copy) {
        Ok(r) => return Some(Box::new(r)),
        Err(copy) => copy,
    };
    let tool = options.external.clone()?;
    ExternalReader::open(ArchiveFormat::Rar, tool, copy).map(|r| Box::new(r) as _)
}

type Each<'f> = dyn FnMut(&ArchiveEntry, Result<MemberData>) -> ControlFlow<()> + 'f;

pub(crate) struct UnrarReader {
    copy: TempCopy,
    entries: Vec<ArchiveEntry>,
    damage: Vec<Damage>,
}

impl UnrarReader {
    /// Lists the archive; gives the copy back when UnRAR cannot read it at all.
    fn open(copy: TempCopy) -> std::result::Result<Self, TempCopy> {
        let Ok(list) = Archive::new(copy.path()).open_for_listing() else { return Err(copy) };
        let mut entries = Vec::new();
        let mut damage = Vec::new();
        for h in list {
            match h {
                Ok(h) => {
                    let mut e = ArchiveEntry::new(entries.len(), h.filename.to_string_lossy());
                    e.size = Some(h.unpacked_size);
                    e.is_dir = h.is_directory();
                    e.encrypted = h.is_encrypted();
                    e.mtime = Timestamp::from_dos((h.file_time >> 16) as u16, h.file_time as u16);
                    if h.is_split() {
                        e.damage.push(Damage::missing(None, "member continues in another volume"));
                    }
                    entries.push(e);
                }
                Err(err) => {
                    damage.push(Damage::new(DamageKind::Corrupt, None, format!("RAR headers: {err}")));
                    break;
                }
            }
        }
        if entries.is_empty() {
            return Err(copy);
        }
        Ok(Self { copy, entries, damage })
    }

    /// Report `msg` for every file entry from `from` on.
    fn fail_rest(&self, from: usize, msg: &str, got: &mut Each<'_>) {
        for entry in self.entries.iter().skip(from).filter(|e| !e.is_dir) {
            if got(entry, Err(Error::Other(msg.to_string()))).is_break() {
                return;
            }
        }
    }

    /// One pass over the archive (solid archives decode in order anyway). `want` gives the
    /// byte limit of entries to read, `None` to skip them.
    fn walk(&self, want: &mut dyn FnMut(&ArchiveEntry) -> Option<usize>, got: &mut Each<'_>) {
        let mut cursor = match Archive::new(self.copy.path()).open_for_processing() {
            Ok(c) => c,
            Err(e) => return self.fail_rest(0, &format!("RAR: {e}"), got),
        };
        let mut index = 0;
        loop {
            let header = match cursor.read_header() {
                Ok(Some(h)) => h,
                Ok(None) => return,
                Err(e) => return self.fail_rest(index, &format!("RAR: {e}"), got),
            };
            let entry = self.entries.get(index);
            index += 1;
            let (Some(entry), Some(limit)) = (entry, entry.and_then(&mut *want)) else {
                match header.skip() {
                    Ok(next) => cursor = next,
                    Err(e) => return self.fail_rest(index, &format!("RAR: {e}"), got),
                }
                continue;
            };
            if entry.encrypted || entry.size.is_some_and(|s| s > limit as u64) {
                let why = if entry.encrypted { "encrypted".to_string() } else { format!("larger than the {limit}-byte member limit") };
                let flow = got(entry, Err(Error::Other(why)));
                match header.skip() {
                    Ok(next) if flow.is_continue() => cursor = next,
                    Ok(_) => return,
                    Err(e) => return self.fail_rest(index, &format!("RAR: {e}"), got),
                }
                continue;
            }
            match header.read() {
                Ok((mut data, next)) => {
                    data.truncate(limit);
                    if got(entry, Ok((data, Vec::new()))).is_break() {
                        return;
                    }
                    cursor = next;
                }
                Err(e) => {
                    if got(entry, Err(Error::Other(format!("{}: {e}", entry.path)))).is_continue() {
                        self.fail_rest(index, "RAR: stream lost after a damaged member", got);
                    }
                    return;
                }
            }
        }
    }
}

impl ArchiveReader for UnrarReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Rar
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        self.entries.clone()
    }

    fn damage(&self) -> Vec<Damage> {
        self.damage.clone()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        let mut found = None;
        self.walk(&mut |e| (e.index == entry.index).then_some(limit), &mut |e, r| {
            if e.index != entry.index {
                return ControlFlow::Continue(());
            }
            found = Some(r);
            ControlFlow::Break(())
        });
        found.unwrap_or_else(|| Err(Error::Other(format!("{}: not reached", entry.path))))
    }

    fn read_all(&self, limit: &dyn Fn(&ArchiveEntry) -> usize, each: &mut dyn FnMut(&ArchiveEntry, Result<MemberData>) -> ControlFlow<()>) {
        self.walk(&mut |e| (!e.is_dir).then(|| limit(e)), each);
    }
}
