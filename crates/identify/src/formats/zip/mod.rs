//! Damage-tolerant ZIP reader: central directory when it survives, local-header rebuild when
//! it does not, per-member damage instead of whole-archive failure.

mod classify;
mod extract;
mod records;

pub use classify::{analyze, validate};
pub use extract::Extracted;

use crate::view::ByteView;
use memchr::memmem;
use records::{CENTRAL_SIG, CentralHeader, EOCD_SIG, Eocd, LOCAL_SIG, LocalHeader};
use serde::{Deserialize, Serialize};
use strata_kernel::{ByteRange, Damage};

/// How the member list was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySource {
    CentralDirectory,
    /// Central directory lost; members rebuilt from local headers.
    LocalHeaders,
    /// Central directory partly damaged; gaps filled from local headers.
    Merged,
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub dos_time: u32,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Position of the local header inside the parsed buffer.
    pub local_header: Option<usize>,
    /// Position of the member data inside the parsed buffer.
    pub data_start: Option<usize>,
    pub in_central: bool,
    pub in_local: bool,
    pub damage: Vec<Damage>,
}

impl ZipEntry {
    pub fn is_encrypted(&self) -> bool {
        self.flags & 1 != 0 || self.method == 99
    }

    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.name.ends_with('\\')
    }

    pub fn method_name(&self) -> &'static str {
        match self.method {
            0 => "stored",
            8 => "deflate",
            9 => "deflate64",
            12 => "bzip2",
            14 => "lzma",
            93 => "zstd",
            95 => "xz",
            98 => "ppmd",
            99 => "aes",
            _ => "other",
        }
    }

    fn from_central(c: &CentralHeader) -> Self {
        Self {
            name: c.name.clone(),
            method: c.method,
            flags: c.flags,
            dos_time: c.dos_time,
            crc32: c.crc32,
            compressed_size: c.compressed,
            uncompressed_size: c.uncompressed,
            local_header: None,
            data_start: None,
            in_central: true,
            in_local: false,
            damage: Vec::new(),
        }
    }

    fn from_local(l: &LocalHeader) -> Self {
        Self {
            name: l.name.clone(),
            method: l.method,
            flags: l.flags,
            dos_time: l.dos_time,
            crc32: l.crc32,
            compressed_size: l.compressed,
            uncompressed_size: l.uncompressed,
            local_header: Some(l.pos),
            data_start: Some(l.data_start),
            in_central: false,
            in_local: true,
            damage: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipArchive {
    entries: Vec<ZipEntry>,
    source: EntrySource,
    zip64: bool,
    /// Archive start inside the buffer (negative when the buffer begins mid-archive).
    start: i64,
    /// Archive end inside the buffer when the end record was found.
    end: Option<usize>,
    damage: Vec<Damage>,
}

impl ZipArchive {
    /// Parse whatever ZIP structure `data` contains. Never fails; check [`ZipArchive::entries`].
    pub fn parse(data: &[u8]) -> Self {
        let locals: Vec<LocalHeader> =
            memmem::find_iter(data, LOCAL_SIG).filter_map(|p| LocalHeader::parse(data, p)).collect();
        let mut archive = Self {
            entries: Vec::new(),
            source: EntrySource::Empty,
            zip64: false,
            start: 0,
            end: None,
            damage: Vec::new(),
        };
        let central = archive.read_central(data);
        archive.merge(data, central, &locals);
        archive
    }

    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    pub fn source(&self) -> EntrySource {
        self.source
    }

    pub fn is_zip64(&self) -> bool {
        self.zip64
    }

    pub fn damage(&self) -> &[Damage] {
        &self.damage
    }

    /// Archive length when the end record was found and the start is inside the buffer.
    pub fn declared_len(&self) -> Option<u64> {
        let end = self.end? as i64;
        (self.start >= 0 && end > self.start).then(|| (end - self.start) as u64)
    }

    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Read the central directory (via the last parseable end record, else by scanning).
    fn read_central(&mut self, data: &[u8]) -> Vec<CentralHeader> {
        let eocd = memmem::rfind_iter(data, EOCD_SIG).find_map(|p| Eocd::parse(data, p));
        let Some(eocd) = eocd else {
            if memmem::find(data, CENTRAL_SIG).is_some() {
                self.damage.push(Damage::missing(None, "end of central directory record not found"));
            }
            return self.scan_central(data, 0, data.len());
        };
        self.zip64 = eocd.zip64;
        self.end = Some(eocd.end);
        let size = usize::try_from(eocd.cd_size).unwrap_or(usize::MAX);
        let cd_pos = eocd.record_start.checked_sub(size).filter(|p| data.get(*p..*p + 4) == Some(CENTRAL_SIG));
        let cd_pos = match cd_pos {
            Some(p) => p,
            None => {
                self.damage.push(Damage::corrupt(
                    ByteRange::new(eocd.pos as u64, 22),
                    "central directory not where the end record says",
                ));
                return self.scan_central(data, 0, eocd.record_start);
            }
        };
        self.start = cd_pos as i64 - eocd.cd_offset as i64;
        let out = self.scan_central(data, cd_pos, eocd.record_start);
        if (out.len() as u64) < eocd.entries {
            self.damage.push(Damage::corrupt(
                ByteRange::new(cd_pos as u64, eocd.cd_size),
                format!("central directory lists {} of {} entries", out.len(), eocd.entries),
            ));
        }
        out
    }

    /// Walk central entries in `[from, to)`, resynchronising on the next signature after damage.
    fn scan_central(&mut self, data: &[u8], from: usize, to: usize) -> Vec<CentralHeader> {
        let region = data.get(from..to.min(data.len())).unwrap_or_default();
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some(rel) = memmem::find(region.get(pos..).unwrap_or_default(), CENTRAL_SIG) {
            let at = from + pos + rel;
            match CentralHeader::parse(data, at) {
                Some(c) => {
                    pos = c.next.saturating_sub(from).max(pos + rel + 4);
                    out.push(c);
                }
                None => pos += rel + 4,
            }
        }
        out
    }

    /// Combine central entries with local headers; local-only members are recovered too.
    fn merge(&mut self, data: &[u8], central: Vec<CentralHeader>, locals: &[LocalHeader]) {
        if self.start == 0
            && let (Some(c), Some(l)) = (central.first(), locals.first())
            && c.name == l.name
        {
            self.start = l.pos as i64 - c.local_offset as i64;
        }
        let mut used = vec![false; locals.len()];
        for c in &central {
            let mut entry = ZipEntry::from_central(c);
            let expected = usize::try_from(self.start + c.local_offset as i64).ok();
            let local = expected
                .and_then(|p| locals.iter().position(|l| l.pos == p))
                .or_else(|| locals.iter().enumerate().position(|(i, l)| !used[i] && l.name == c.name));
            match local {
                Some(i) => {
                    used[i] = true;
                    entry.in_local = true;
                    entry.local_header = Some(locals[i].pos);
                    entry.data_start = Some(locals[i].data_start);
                }
                None => entry.damage.push(Damage::missing(
                    expected.map(|p| ByteRange::new(p as u64, 30)),
                    "local header missing or overwritten",
                )),
            }
            self.entries.push(entry);
        }
        // Local headers inside another member's data belong to a nested archive, not to us.
        let spans: Vec<(usize, usize)> = self
            .entries
            .iter()
            .filter_map(|e| Some((e.data_start?, e.data_start?.saturating_add(e.compressed_size as usize))))
            .collect();
        let nested = |p: usize| spans.iter().any(|(s, e)| p >= *s && p < *e);
        let orphans: Vec<&LocalHeader> =
            locals.iter().zip(&used).filter(|(l, u)| !**u && !nested(l.pos)).map(|(l, _)| l).collect();
        self.source = match (central.is_empty(), orphans.is_empty()) {
            (true, true) => EntrySource::Empty,
            (true, false) => EntrySource::LocalHeaders,
            (false, true) => EntrySource::CentralDirectory,
            (false, false) => EntrySource::Merged,
        };
        for l in orphans {
            let mut entry = ZipEntry::from_local(l);
            if l.has_descriptor() || l.compressed == 0 {
                extract::resolve_descriptor(data, &mut entry);
            }
            self.entries.push(entry);
        }
        self.entries.sort_by_key(|e| e.local_header.unwrap_or(usize::MAX));
    }
}

/// End of a ZIP archive that starts at offset 0 of `view`: the first end record whose central
/// directory offset is consistent with that start.
pub fn end_of_archive(view: &dyn ByteView, cap: u64) -> Option<u64> {
    let mut from = 0;
    while let Some(at) = view.find(EOCD_SIG, from, cap) {
        from = at + 1;
        // Window holding an optional ZIP64 record + locator before, and the comment after.
        let before = at.min(76);
        let window = view.bytes(at - before, before as usize + 22 + 65535);
        let Some(e) = Eocd::parse(&window, before as usize) else { continue };
        let record_start = at - before + e.record_start as u64;
        if e.cd_offset.checked_add(e.cd_size) == Some(record_start) {
            return Some(at - before + e.end as u64);
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests;
