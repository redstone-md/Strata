//! Locating and streaming the `$MFT`, which may itself be fragmented over several runs and
//! extension records.

use super::attr::{ATTRIBUTE_LIST, Attribute, DATA};
use super::boot::NtfsBoot;
use super::meta::ListEntry;
use super::record::MftRecord;
use super::stream::Stream;
use crate::{EntryState, Extent, ExtentReader, FileEntry};
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

const CHUNK: usize = 1 << 20;
const MAX_LIST_BYTES: usize = 1 << 20;

pub(super) struct Mft {
    file: FileEntry,
    record_size: usize,
}

impl Mft {
    /// From the `$MFT` record at the boot sector's LCN, else from the `$MFTMirr` copy.
    pub(super) fn locate(source: &dyn BlockSource, boot: &NtfsBoot) -> (Option<Self>, Vec<Damage>) {
        if let Some(found) = Self::from_record0(source, boot, boot.mft_offset()) {
            return (Some(found.0), found.1);
        }
        let note = Damage::corrupt(ByteRange::new(boot.mft_offset(), boot.record_size() as u64), "$MFT record 0 unusable");
        match Self::from_record0(source, boot, boot.mirror_offset()) {
            Some((mft, mut damage)) => {
                damage.insert(0, note);
                damage.push(Damage::new(DamageKind::Corrupt, None, "$MFT located through $MFTMirr"));
                (Some(mft), damage)
            }
            None => (None, vec![note]),
        }
    }

    fn read_record(source: &dyn BlockSource, offset: u64, size: usize, number: u64) -> Option<MftRecord> {
        let mut raw = source.read_vec(offset, size).ok().filter(|r| r.len() == size)?;
        MftRecord::parse(&mut raw, number, offset, false)
    }

    fn from_record0(source: &dyn BlockSource, boot: &NtfsBoot, offset: u64) -> Option<(Self, Vec<Damage>)> {
        let rs = boot.record_size();
        let base = Self::read_record(source, offset, rs, 0).filter(MftRecord::in_use)?;
        let at = ByteRange::new(offset, rs as u64);
        let mut damage = base.damage().to_vec();
        let mut extension: Vec<MftRecord> = Vec::new();
        for number in Self::listed_data_records(source, boot, &base, at) {
            let attrs = Self::data_attrs(&base, &extension);
            let partial = Self { file: Self::as_file(Stream::unnamed(&attrs, DATA, boot, at)?), record_size: rs };
            match partial.record_volume_offset(number).and_then(|o| Self::read_record(source, o, rs, number)) {
                Some(rec) if rec.base().is_some_and(|b| b.record() == 0) => extension.push(rec),
                _ => damage.push(Damage::missing(None, format!("$MFT extension record {number} unreadable"))),
            }
        }
        let stream = Stream::unnamed(&Self::data_attrs(&base, &extension), DATA, boot, at)?;
        if stream.size() < rs as u64 * 16 {
            return None;
        }
        let file = Self::as_file(stream);
        damage.extend(file.damage.iter().cloned());
        Some((Self { file, record_size: rs }, damage))
    }

    fn data_attrs<'a>(base: &'a MftRecord, extension: &'a [MftRecord]) -> Vec<&'a Attribute> {
        std::iter::once(base).chain(extension).flat_map(|r| r.attrs()).filter(|a| a.type_code() == DATA).collect()
    }

    /// Extension records holding further `$MFT` `$DATA` runs, per record 0's attribute list.
    fn listed_data_records(source: &dyn BlockSource, boot: &NtfsBoot, base: &MftRecord, at: ByteRange) -> Vec<u64> {
        let attrs: Vec<&Attribute> = base.attrs().iter().collect();
        let Some(list) = Stream::unnamed(&attrs, ATTRIBUTE_LIST, boot, at) else { return Vec::new() };
        let mut out = Vec::new();
        for e in ListEntry::parse_all(&list.read(source, MAX_LIST_BYTES)) {
            let n = e.record().record();
            if e.type_code() == DATA && e.name().is_empty() && n != 0 && !out.contains(&n) {
                out.push(n);
            }
        }
        out
    }

    fn as_file(stream: Stream) -> FileEntry {
        let size = stream.size();
        let (extents, resident, damage) = stream.into_parts();
        let mut file = FileEntry::new("$MFT", false, EntryState::Allocated, 0);
        file.size = size;
        file.extents = extents;
        file.resident = resident;
        file.damage = damage;
        file
    }

    pub(super) fn extents(&self) -> &[Extent] {
        &self.file.extents
    }

    pub(super) fn record_volume_offset(&self, number: u64) -> Option<u64> {
        let pos = number.checked_mul(self.record_size as u64)?;
        self.file.extents.iter().find_map(|e| {
            let inside = pos >= e.file_offset && pos + self.record_size as u64 <= e.file_offset + e.len;
            inside.then_some(e.volume_offset?).map(|v| v + (pos - e.file_offset))
        })
    }

    /// Parse every record in order, handing each to `sink`. Never-used (zeroed) slots are
    /// skipped, and so are sparse holes, so a garbage `$MFT` size cannot make this spin.
    pub(super) fn read_records(&self, source: &dyn BlockSource, mut sink: impl FnMut(MftRecord)) -> Vec<Damage> {
        let rs = self.record_size as u64;
        let chunk = (CHUNK as u64 / rs).max(1) * rs;
        let reader = ExtentReader::new(source, &self.file);
        let mut damage = Vec::new();
        let mut buf = vec![0u8; chunk as usize];
        for ext in &self.file.extents {
            let Some(vol) = ext.volume_offset else { continue };
            let end = ext.file_offset + ext.len;
            let mut pos = ext.file_offset.div_ceil(rs) * rs;
            while pos < end {
                let whole = ((end - pos) / rs * rs).min(chunk);
                // A record crossing into the next fragment is read through the extent map.
                let (n, read) = if whole > 0 {
                    (whole, source.read_at(vol + (pos - ext.file_offset), &mut buf[..whole as usize]))
                } else {
                    (rs, reader.read(pos, &mut buf[..rs as usize]))
                };
                if let Err(e) = read {
                    damage.push(Damage::new(DamageKind::Unreadable, None, format!("$MFT read at {pos:#x} failed: {e}")));
                }
                for (i, raw) in buf[..n as usize].chunks_exact_mut(rs as usize).enumerate() {
                    let number = pos / rs + i as u64;
                    let at = vol + (pos - ext.file_offset) + i as u64 * rs;
                    if let Some(rec) = MftRecord::parse(raw, number, at, false) {
                        sink(rec);
                    }
                }
                pos += n;
            }
        }
        for bad in source.damage() {
            for e in &self.file.extents {
                let Some(v) = e.volume_offset else { continue };
                if let Some(hit) = ByteRange::new(v, e.len).intersect(&bad) {
                    damage.push(Damage::new(DamageKind::Unreadable, Some(hit), "$MFT region unreadable; records there lost"));
                }
            }
        }
        damage
    }
}
