//! Turns one base MFT record (plus its extension records) into a [`FileEntry`].

use super::attr::{Attribute, DATA, FILE_NAME, STANDARD_INFORMATION};
use super::boot::NtfsBoot;
use super::meta::{FileName, standard_times};
use super::record::{FileRef, MftRecord};
use super::stream::Stream;
use crate::{EntryState, FileEntry};
use strata_kernel::{ByteRange, Damage};

/// A file built from its records, before it is placed in the tree.
pub(super) struct Built {
    entry: FileEntry,
    parent: Option<FileRef>,
    seq: u16,
    in_use: bool,
    compression_unit: Option<u64>,
}

impl Built {
    pub(super) fn parent(&self) -> Option<FileRef> {
        self.parent
    }

    pub(super) fn seq(&self) -> u16 {
        self.seq
    }

    pub(super) fn in_use(&self) -> bool {
        self.in_use
    }

    pub(super) fn compression_unit(&self) -> Option<u64> {
        self.compression_unit
    }

    pub(super) fn entry_mut(&mut self) -> &mut FileEntry {
        &mut self.entry
    }

    pub(super) fn into_entry(self) -> FileEntry {
        self.entry
    }
}

pub(super) struct Assembler<'a> {
    boot: &'a NtfsBoot,
}

impl<'a> Assembler<'a> {
    pub(super) fn new(boot: &'a NtfsBoot) -> Self {
        Self { boot }
    }

    /// `None` for free records that no longer carry a name (nothing worth showing).
    pub(super) fn build(&self, base: &MftRecord, extensions: &[&MftRecord], volume_offset: u64) -> Option<Built> {
        let at = ByteRange::new(volume_offset, self.boot.record_size() as u64);
        let attrs: Vec<&Attribute> =
            base.attrs().iter().chain(extensions.iter().flat_map(|r| r.attrs().iter())).collect();
        let names: Vec<FileName> = attrs
            .iter()
            .filter(|a| a.type_code() == FILE_NAME)
            .filter_map(|a| a.resident_value())
            .filter_map(FileName::parse)
            .collect();
        let best = names.iter().min_by_key(|n| n.rank());
        // Free records without a name, and the empty reserved records (12..16), carry nothing.
        let has_content = attrs.iter().filter(|a| a.type_code() == DATA).any(|a| {
            a.resident_value().map_or_else(|| a.non_resident().is_some_and(|n| n.size() > 0), |v| !v.is_empty())
        });
        if best.is_none() && (!base.in_use() || !has_content) {
            return None;
        }
        let name = best.map_or_else(|| format!("$Record{}", base.number()), |n| n.name().to_string());
        let is_dir = base.is_dir() || best.is_some_and(FileName::is_dir);
        let state = if base.in_use() { EntryState::Allocated } else { EntryState::Deleted };
        let mut entry = FileEntry::new(name, is_dir, state, base.number());
        let si = attrs
            .iter()
            .filter(|a| a.type_code() == STANDARD_INFORMATION)
            .find_map(|a| a.resident_value().and_then(standard_times));
        entry.times = si.or(best.map(FileName::times)).unwrap_or_default();
        entry.damage.extend(base.damage().iter().cloned());
        entry.damage.extend(extensions.iter().flat_map(|r| r.damage().iter().cloned()));
        if best.is_none() {
            entry.damage.push(Damage::missing(Some(at), "record has no $FILE_NAME"));
        }
        let compression_unit = self.attach_streams(&mut entry, &attrs, at);
        Some(Built { entry, parent: best.map(FileName::parent), seq: base.seq(), in_use: base.in_use(), compression_unit })
    }

    /// Unnamed `$DATA` becomes the content, named ones become `name:stream` streams.
    fn attach_streams(&self, entry: &mut FileEntry, attrs: &[&Attribute], at: ByteRange) -> Option<u64> {
        let mut compression_unit = None;
        for stream in Stream::collect(attrs, DATA, self.boot, at) {
            let size = stream.size();
            let unit = stream.compression_unit();
            let label = format!("{}:{}", entry.name, stream.name());
            let unnamed = stream.name().is_empty();
            let resident_at = stream.resident_at();
            let (extents, resident, damage) = stream.into_parts();
            entry.damage.extend(damage);
            if unnamed {
                entry.size = size;
                entry.extents = extents;
                entry.resident = resident;
                entry.resident_offset = resident_at;
                // Extents then hold LZNT1 units; the filesystem decompresses on read.
                compression_unit = unit;
            } else {
                if resident.is_some() {
                    entry.damage.push(Damage::missing(Some(at), format!("resident stream {label} not exposed")));
                }
                entry.streams.push((label, extents, size));
            }
        }
        compression_unit
    }
}
