//! Side tables: file-signature hits and recognised boot records found anywhere on the disk.

use serde::{Deserialize, Serialize};
use serde_json::json;
use strata_identify::{SignatureDetector, TypeId};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{ByteRange, Confidence};
use strata_volume::FsKind;

/// Where a side-table entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySource {
    /// Strata's own scan pass.
    Scan,
    /// Imported from an R-Studio scan file; a hint until our own pass or check confirms it.
    RStudio,
}

impl EntrySource {
    pub(crate) fn to_bits(self) -> u8 {
        match self {
            EntrySource::Scan => 0,
            EntrySource::RStudio => 1,
        }
    }

    pub(crate) fn from_bits(v: u8) -> Self {
        if v & 1 == 1 { EntrySource::RStudio } else { EntrySource::Scan }
    }
}

/// A file start. `type_key` is a `strata_identify` type key, or `rstudio:<TAG>` for an
/// R-Studio file type Strata has no equivalent for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureHit {
    pub offset: u64,
    /// Bytes the magic spans (the detector hit's `len`).
    pub match_len: u16,
    pub type_key: String,
    pub declared_len: Option<u64>,
    pub confidence: f32,
    pub validated: bool,
    pub source: EntrySource,
}

impl SignatureHit {
    /// Compact form of a `SignatureDetector` hit; `None` for any other hit.
    pub fn from_detector_hit(hit: &Hit) -> Option<Self> {
        if hit.category != HitCategory::FileSignature {
            return None;
        }
        let type_key = hit.details.get("type_id")?.as_str()?.to_string();
        Some(Self {
            offset: hit.offset,
            match_len: u16::try_from(hit.len).unwrap_or(u16::MAX),
            type_key,
            declared_len: hit.details.get("declared_len").and_then(|v| v.as_u64()),
            confidence: hit.confidence.get(),
            validated: hit.details.get("validated").and_then(|v| v.as_bool()).unwrap_or(false),
            source: EntrySource::Scan,
        })
    }

    /// Rebuild the detector hit (same id, label, value and details as `SignatureDetector`
    /// emits), so consumers such as the carver cannot tell where it came from.
    pub fn to_detector_hit(&self) -> Option<Hit> {
        let id = TypeId::from_key(&self.type_key)?;
        let spec = id.spec();
        Some(
            Hit::new(SignatureDetector::ID, HitCategory::FileSignature, self.offset, usize::from(self.match_len))
                .confidence(Confidence::new(self.confidence))
                .label(spec.name)
                .value(format!("{}@{:#x}", spec.key, self.offset))
                .details(json!({
                    "type_id": spec.key,
                    "category": spec.category,
                    "declared_len": self.declared_len,
                    "validated": self.validated,
                })),
        )
    }
}

/// A boot sector or superblock: the volume it declares starts at `volume_start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootRecord {
    /// Where the record itself was found.
    pub found_at: u64,
    /// Start of the volume it describes (differs from `found_at` for backups and ext
    /// superblocks).
    pub volume_start: u64,
    pub declared_len: u64,
    pub fs: FsKind,
    pub source: EntrySource,
}

impl BootRecord {
    pub fn volume(&self) -> ByteRange {
        ByteRange::new(self.volume_start, self.declared_len)
    }

    pub(crate) fn fs_to_bits(fs: FsKind) -> u8 {
        FS_KINDS.iter().position(|k| *k == fs).unwrap_or(FS_KINDS.len() - 1) as u8
    }

    pub(crate) fn fs_from_bits(v: u8) -> FsKind {
        FS_KINDS.get(usize::from(v)).copied().unwrap_or(FsKind::Unknown)
    }
}

/// Stable on-disk numbering of filesystem kinds (append only).
const FS_KINDS: [FsKind; 9] = [
    FsKind::Ntfs,
    FsKind::Fat12,
    FsKind::Fat16,
    FsKind::Fat32,
    FsKind::ExFat,
    FsKind::Ext2,
    FsKind::Ext3,
    FsKind::Ext4,
    FsKind::Unknown,
];

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::scan::Detector;

    #[test]
    fn detector_hits_round_trip_through_the_compact_form() {
        let mut data = vec![0u8; 4096];
        data[512..520].copy_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        data[520..528].copy_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        let mut hits = Vec::new();
        SignatureDetector::new().scan(&data, 1 << 20, &mut hits);
        let hit = hits.first().expect("png signature");
        let compact = SignatureHit::from_detector_hit(hit).unwrap();
        let back = compact.to_detector_hit().unwrap();
        assert_eq!((back.offset, back.len, &back.label, &back.value), (hit.offset, hit.len, &hit.label, &hit.value));
        assert_eq!(back.details, hit.details);
        assert_eq!(back.confidence.get(), hit.confidence.get());
    }

    #[test]
    fn fs_kind_numbering_is_total() {
        for k in FS_KINDS {
            assert_eq!(BootRecord::fs_from_bits(BootRecord::fs_to_bits(k)), k);
        }
        assert_eq!(BootRecord::fs_from_bits(200), FsKind::Unknown);
    }
}
