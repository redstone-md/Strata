//! R-Studio scan files (`.scn`): what R-Studio already found on a disk, read so the user can
//! browse before (and while) Strata's own pass runs. Everything taken from here is a hint:
//! volumes are verified against the disk before use and index content stays marked seeded
//! until our pass profiles the block. See `FORMAT-scn.md` for the reverse-engineered layout.

mod container;
mod elements;
mod objects;
mod seed;
mod signatures;
#[doc(hidden)]
pub mod testkit;
mod types;

pub use signatures::ScnRegion;
pub use types::type_for_tag;

use crate::side::BootRecord;
use container::{Container, TAG_OBJECT, TAG_PROGRESS, TAG_SCANNED_OBJECT};
use objects::Object;
use serde::Serialize;
use signatures::StreamDecoder;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use strata_kernel::{ByteRange, Damage, DamageKind, Error, Result};
use strata_volume::FsKind;

/// Where a recognised volume came from inside the scan file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScnVolumeOrigin {
    /// A partition object under the scanned device (partition table or R-Studio's own find).
    PartitionObject,
    /// An NTFS boot sector (primary or backup reading) from the scan elements.
    NtfsBootRecord,
    /// A FAT boot sector from the scan elements (length unknown until verified).
    FatBootRecord,
}

/// A volume R-Studio knew about. A candidate only: check it against the disk before use.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScnVolume {
    pub range: ByteRange,
    pub fs: FsKind,
    pub origin: ScnVolumeOrigin,
    /// How much the scan file alone supports the candidate (0..=1).
    pub confidence: f32,
    pub label: Option<String>,
    /// MBR partition type byte, when the object has one.
    pub partition_type: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ScnMetadata {
    pub version: u32,
    pub device_name: Option<String>,
    pub disk_len: Option<u64>,
    pub sector_size: Option<u64>,
    /// Highest progress mark: bytes R-Studio had scanned.
    pub scanned_to: Option<u64>,
    /// Group counts by kind (`TONI`, `OOGR`, `TF/4`, ...).
    pub groups: BTreeMap<String, u64>,
    /// Kinds present in the file that this reader does not interpret.
    pub undecoded: Vec<String>,
    /// File-type entries decoded (before merging repeats and text pieces).
    pub file_type_entries: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ScnInfo {
    pub metadata: ScnMetadata,
    pub recognized_volumes: Vec<ScnVolume>,
    /// Boot sectors R-Studio found (NTFS readings and FAT), as index side-table entries.
    pub boot_records: Vec<BootRecord>,
    /// File starts and text runs, in stream order.
    pub signature_regions: Vec<ScnRegion>,
    #[serde(skip)]
    pub damage: Vec<Damage>,
}

/// Element kinds this reader interprets.
const DECODED: &[&str] = &["TONI", "ESNI", "OOGR", "TF/4", "TF/2", "TN/3", "AF/3"];

pub struct ScnFile;

impl ScnFile {
    pub fn open(path: &Path) -> Result<ScnInfo> {
        Self::parse(&std::fs::read(path)?)
    }

    /// The scan file R-Studio keeps next to an image: `<stem>.scn` (or `<name>.scn`).
    pub fn beside(image: &Path) -> Option<PathBuf> {
        [image.with_extension("scn"), PathBuf::from(format!("{}.scn", image.display()))].into_iter().find(|p| p.is_file())
    }

    /// Decode a scan file image. `Err` only when it is not a scan file at all.
    pub fn parse(data: &[u8]) -> Result<ScnInfo> {
        let c = Container::parse(data).ok_or_else(|| Error::format("not an R-Studio scan file"))?;
        let mut info = ScnInfo { damage: c.damage, ..Default::default() };
        info.metadata.version = c.version;
        let mut objects = Vec::new();
        let mut scanned = None;
        let mut stream = Vec::new();
        let (mut ntfs, mut fat) = (Vec::new(), Vec::new());
        for g in &c.groups {
            let name = g.name();
            *info.metadata.groups.entry(name.clone()).or_default() += 1;
            if !DECODED.contains(&name.as_str()) && !info.metadata.undecoded.contains(&name) {
                info.metadata.undecoded.push(name.clone());
            }
            match (g.tag, g.element()) {
                (TAG_OBJECT | TAG_SCANNED_OBJECT, _) => {
                    let (o, clean) = Object::parse(g.payload);
                    if !clean {
                        info.damage.push(Damage::new(DamageKind::Truncated, None, format!("scan file: object group at {:#x} cut short", g.offset)));
                    }
                    if g.tag == TAG_SCANNED_OBJECT {
                        scanned = Some(objects.len());
                    }
                    objects.push(o);
                }
                (TAG_PROGRESS, _) => {
                    let mark = elements::progress(g.payload);
                    info.metadata.scanned_to = info.metadata.scanned_to.max(mark);
                }
                (_, Some((4, [b'T', b'F']))) => stream.extend_from_slice(g.payload),
                (_, Some((3, [b'T', b'N']))) => ntfs.push(g.payload),
                (_, Some((3, [b'A', b'F']))) => fat.push(g.payload),
                _ => {}
            }
        }
        let device = scanned.and_then(|i| objects.get(i));
        if let Some(d) = device {
            info.metadata.device_name = d.name();
            info.metadata.disk_len = d.size();
            info.metadata.sector_size = d.sector_size();
        }
        let disk_len = info.metadata.disk_len;
        info.recognized_volumes = partitions(&objects, device, disk_len);
        for p in &ntfs {
            info.boot_records.extend(elements::ntfs_boot_records(p, disk_len));
        }
        for p in &fat {
            info.boot_records.extend(elements::fat_boot_records(p, disk_len));
        }
        add_boot_volumes(&mut info.recognized_volumes, &info.boot_records);
        let decoded = StreamDecoder::new(info.metadata.sector_size.unwrap_or(512), disk_len).decode(&stream);
        if decoded.skipped_bytes > 0 {
            info.damage.push(Damage::new(
                DamageKind::Corrupt,
                None,
                format!("scan file: {} bytes of file-type entries not decoded", decoded.skipped_bytes),
            ));
        }
        info.metadata.file_type_entries = decoded.entries;
        info.signature_regions = decoded.regions;
        Ok(info)
    }
}

/// Partition objects below the scanned device (any depth; starts are taken relative to the
/// parent object). Objects of other devices in the tree are ignored.
fn partitions(objects: &[Object<'_>], device: Option<&Object<'_>>, disk_len: Option<u64>) -> Vec<ScnVolume> {
    let Some(root) = device.and_then(Object::id) else { return Vec::new() };
    let mut out: Vec<ScnVolume> = Vec::new();
    let mut frontier = vec![(root, 0u64)];
    let mut seen = vec![root];
    while let Some((parent, base)) = frontier.pop() {
        for o in objects.iter().filter(|o| o.parent() == Some(parent)) {
            let (Some(id), Some(start), Some(len)) = (o.id(), o.start(), o.size()) else { continue };
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            let range = ByteRange::new(base.saturating_add(start), len);
            frontier.push((id, range.start()));
            if len == 0 || disk_len.is_some_and(|d| range.end() > d) || out.iter().any(|v| v.range == range) {
                continue;
            }
            let fs = o.fs_name().map_or(FsKind::Unknown, |n| elements::fs_from_name(&n));
            out.push(ScnVolume {
                range,
                fs,
                origin: ScnVolumeOrigin::PartitionObject,
                confidence: 0.9,
                label: o.fs_name(),
                partition_type: o.partition_type(),
            });
        }
    }
    out.sort_by_key(|v| v.range.start());
    out
}

/// Volumes implied by boot records that no partition object already covers.
fn add_boot_volumes(volumes: &mut Vec<ScnVolume>, boots: &[BootRecord]) {
    for b in boots {
        if volumes.iter().any(|v| v.range.start() == b.volume_start) {
            continue;
        }
        let (origin, confidence) = match (b.fs, b.found_at == b.volume_start) {
            (FsKind::Ntfs, true) => (ScnVolumeOrigin::NtfsBootRecord, 0.7),
            (FsKind::Ntfs, false) => (ScnVolumeOrigin::NtfsBootRecord, 0.6),
            _ => (ScnVolumeOrigin::FatBootRecord, 0.5),
        };
        volumes.push(ScnVolume { range: ByteRange::new(b.volume_start, b.declared_len), fs: b.fs, origin, confidence, label: None, partition_type: None });
    }
}

#[cfg(test)]
mod tests;
