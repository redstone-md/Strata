//! Attribute content as a stream: resident bytes or non-resident extents, possibly spread over
//! several attribute instances (extension records).

use super::attr::{Attribute, NonResident};
use super::boot::NtfsBoot;
use super::runs;
use crate::alloc::ExtentList;
use crate::{EntryState, Extent, ExtentReader, FileEntry};
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

const MAX_UNIT: u64 = 1 << 20;

pub(super) struct Stream {
    name: String,
    size: u64,
    extents: Vec<Extent>,
    resident: Option<Vec<u8>>,
    /// Bytes per compression unit for LZNT1-compressed streams.
    compression_unit: Option<u64>,
    damage: Vec<Damage>,
}

impl Stream {
    /// Group the attributes of `type_code` by name into streams, in first-seen order.
    pub(super) fn collect(attrs: &[&Attribute], type_code: u32, boot: &NtfsBoot, at: ByteRange) -> Vec<Stream> {
        let mut names: Vec<&str> = Vec::new();
        for a in attrs.iter().filter(|a| a.type_code() == type_code) {
            if !names.contains(&a.name()) {
                names.push(a.name());
            }
        }
        names
            .into_iter()
            .map(|name| {
                let group: Vec<&Attribute> =
                    attrs.iter().copied().filter(|a| a.type_code() == type_code && a.name() == name).collect();
                Self::build(name, &group, boot, at)
            })
            .collect()
    }

    /// The unnamed stream of `type_code`, if any.
    pub(super) fn unnamed(attrs: &[&Attribute], type_code: u32, boot: &NtfsBoot, at: ByteRange) -> Option<Stream> {
        Self::collect(attrs, type_code, boot, at).into_iter().find(|s| s.name.is_empty())
    }

    fn build(name: &str, group: &[&Attribute], boot: &NtfsBoot, at: ByteRange) -> Stream {
        let mut stream = Stream {
            name: name.to_string(),
            size: 0,
            extents: Vec::new(),
            resident: None,
            compression_unit: None,
            damage: Vec::new(),
        };
        if let Some(value) = group.iter().find_map(|a| a.resident_value()) {
            stream.size = value.len() as u64;
            stream.resident = Some(value.to_vec());
            return stream;
        }
        let instances: Vec<&NonResident> = group.iter().filter_map(|a| a.non_resident()).collect();
        let Some(first) = instances.iter().find(|n| n.start_vcn() == 0).or(instances.first()) else {
            return stream;
        };
        stream.size = first.size();
        let mut list = ExtentList::default();
        let outside = runs::layout(&instances, boot, &mut list);
        if outside > 0 {
            stream.damage.push(Damage::corrupt(at, format!("{outside} data run(s) point past the volume end")));
        }
        if instances.iter().any(|n| !n.runs_clean()) {
            stream.damage.push(Damage::corrupt(at, "data run list damaged; content partial"));
        }
        if list.end() < stream.size {
            stream.damage.push(Damage::missing(Some(at), "runs cover less than the stream size (extension record lost?)"));
        }
        let compressed = group.iter().any(|a| a.is_compressed()) && first.compression_unit() > 0;
        if compressed {
            // NTFS always uses 16-cluster units; anything far larger is garbage, capped to stay cheap.
            let unit = (boot.cluster_size() << first.compression_unit().min(8)).min(MAX_UNIT);
            let span = stream.size.div_ceil(unit).saturating_mul(unit);
            stream.compression_unit = Some(unit);
            stream.extents = list.finish(span, span);
        } else {
            stream.extents = list.finish(stream.size, first.initialized());
        }
        if group.iter().any(|a| a.is_encrypted()) {
            stream.damage.push(Damage::new(DamageKind::Corrupt, Some(at), "EFS encrypted; content is ciphertext"));
        }
        stream
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn compression_unit(&self) -> Option<u64> {
        self.compression_unit
    }

    pub(super) fn into_parts(self) -> (Vec<Extent>, Option<Vec<u8>>, Vec<Damage>) {
        (self.extents, self.resident, self.damage)
    }

    /// Read up to `limit` bytes of an uncompressed stream.
    pub(super) fn read(&self, source: &dyn BlockSource, limit: usize) -> Vec<u8> {
        let mut entry = FileEntry::new(self.name.clone(), false, EntryState::Allocated, 0);
        entry.size = self.size;
        entry.extents = self.extents.clone();
        entry.resident = self.resident.clone();
        ExtentReader::new(source, &entry).read_all(limit).unwrap_or_default()
    }
}
