//! The file index against the volumes it came from: volumes Strata could not list, a file
//! table far smaller than the volume, an MFT with room for many more records than were read,
//! and volumes dominated by deleted or orphaned entries.

use super::{Check, SMALL_VOLUME, older_data};
use crate::inputs::{DiskInputs, VolumeInputs};
use crate::observation::{Bearing, Observation, Severity, Signal};
use crate::units::{bytes, count, day, percent, share};

/// Live files filling less than this share of a volume: the file table cannot be the whole
/// story.
const SPARSE_SHARE: f64 = 0.01;
/// Below this share a volume is "mostly empty" (a notice, not an alarm).
const EMPTY_SHARE: f64 = 0.05;
/// Unrecognised volumes at least this big are worth a word (smaller ones are reserved areas).
const UNKNOWN_VOLUME: u64 = 1 << 30;
/// An MFT with room for this many times the entries read, and at least
/// [`MISSING_RECORDS`] more, was not fully read. (4 KiB records over-estimate room fourfold.)
const MFT_RATIO: u64 = 5;
const MISSING_RECORDS: u64 = 1000;
/// Deleted files outnumbering live ones count once there are this many.
const DELETED_MAJORITY: u64 = 500;
/// Orphans worth a word: this many, or this share of entries once there are
/// [`SOME_ORPHANS`].
const MANY_ORPHANS: u64 = 1000;
const SOME_ORPHANS: u64 = 100;
const ORPHAN_SHARE: f64 = 0.1;

pub(crate) struct FileTableCheck;

impl Check for FileTableCheck {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>) {
        if !disk.indexed {
            out.push(Observation::new(
                Severity::Info,
                Signal::NotIndexed,
                "Files not indexed yet",
                "The file index has not finished for this disk, so file counts below are incomplete. Press Analyse to index it.",
            ));
        }
        if disk.volumes.is_empty() && disk.disk_len > 0 {
            out.push(
                Observation::new(
                    Severity::Alert,
                    Signal::UnknownFileSystem,
                    "No partitions or file systems found",
                    "Strata found no partition table and no file system on this disk. It may be wiped, encrypted as a whole, \
                     or damaged at the start. Only the raw scan and carving looked at it.",
                )
                .figure("Disk size", bytes(disk.disk_len))
                .bearing(Bearing::Unreadable),
            );
        }
        let readable = disk.volumes.iter().any(|v| v.recognised && v.live.files > 0);
        // Deleted partitions found by the sweep are judged by what they still hold, not
        // against their size: most of them were partly overwritten long ago.
        for v in disk.volumes.iter().filter(|v| !v.recovered) {
            if !v.recognised {
                unknown(v, readable, out);
            } else if disk.indexed && v.entries() == 0 && v.len >= SMALL_VOLUME {
                out.push(unread(v));
            } else if v.entries() > 0 {
                listed(disk, v, out);
            }
        }
    }
}

fn unknown(v: &VolumeInputs, readable: bool, out: &mut Vec<Observation>) {
    if v.len < UNKNOWN_VOLUME {
        return;
    }
    let o = Observation::new(
        Severity::Warning,
        Signal::UnknownFileSystem,
        format!("Volume {}: file system not recognised", v.index),
        format!(
            "Strata does not know the file system of this {} volume. It may be encrypted (BitLocker, VeraCrypt), \
             of a kind Strata does not read, or damaged. Its files are not listed; only the raw scan and carving looked at it.",
            bytes(v.len)
        ),
    )
    .on(v.index)
    .figure("Volume size", bytes(v.len));
    out.push(if readable { o } else { o.bearing(Bearing::Unreadable) });
}

fn unread(v: &VolumeInputs) -> Observation {
    Observation::new(
        Severity::Alert,
        Signal::UnreadVolume,
        format!("Strata could not read the file system of volume {}", v.index),
        format!(
            "Volume {} is {} of {}, but the file index holds nothing for it. The file system is damaged or Strata failed to \
             read it. Files there appear in no list; only the raw scan and carving looked at it.",
            v.index,
            bytes(v.len),
            v.fs
        ),
    )
    .on(v.index)
    .figure("Volume size", bytes(v.len))
    .figure("Entries indexed", "0")
    .bearing(Bearing::Unreadable)
}

/// Checks of a volume the index holds entries for.
fn listed(disk: &DiskInputs, v: &VolumeInputs, out: &mut Vec<Observation>) {
    let missing = missing_records(v);
    let fill = share(v.live.bytes, v.len);
    if v.len >= SMALL_VOLUME && fill < SPARSE_SHARE {
        out.push(sparse(disk, v, missing.is_some()));
    } else if v.len >= 4 * SMALL_VOLUME && fill < EMPTY_SHARE {
        out.push(
            Observation::new(
                Severity::Notice,
                Signal::MostlyEmpty,
                format!("Volume {} mostly empty: files fill {}", v.index, percent(v.live.bytes, v.len)),
                format!(
                    "The live files of this {} volume add up to {}. A disk in daily use is rarely this empty; it may be a \
                     spare or data disk, or most of its contents were deleted.",
                    bytes(v.len),
                    bytes(v.live.bytes)
                ),
            )
            .on(v.index)
            .figure("Volume size", bytes(v.len))
            .figure("Live files", count(v.live.files))
            .figure("Live data", bytes(v.live.bytes)),
        );
    }
    out.extend(missing);
    let gone = v.deleted.files + v.orphan.files;
    if gone >= DELETED_MAJORITY && gone > v.live.files {
        out.push(
            Observation::new(
                Severity::Warning,
                Signal::DeletedMajority,
                format!("Volume {}: more deleted than live files", v.index),
                "The file table still lists more deleted files than live ones. Much of what this volume held was deleted, \
                 by hand, by a cleaning program, or before a reinstall. Deleted files are listed in Files and may still be \
                 recoverable.",
            )
            .on(v.index)
            .figure("Deleted files", count(gone))
            .figure("Live files", count(v.live.files)),
        );
    }
    let orphans = v.orphan.files;
    if orphans >= MANY_ORPHANS || (orphans >= SOME_ORPHANS && share(orphans, v.entries()) >= ORPHAN_SHARE) {
        out.push(
            Observation::new(
                Severity::Notice,
                Signal::Orphans,
                format!("Volume {}: {} orphaned files", v.index, count(orphans)),
                "These deleted files lost the folder they were in: the folder records were reused or damaged. Typical of a \
                 file table that was partly overwritten, by heavy use after deletion or a reformat.",
            )
            .on(v.index)
            .figure("Orphaned files", count(orphans))
            .figure("Entries", count(v.entries())),
        );
    }
}

/// The MFT has room for far more records than were read.
fn missing_records(v: &VolumeInputs) -> Option<Observation> {
    let room = v.file_table?.records();
    let read = v.entries();
    (room >= MFT_RATIO * read && room - read >= MISSING_RECORDS).then(|| {
        Observation::new(
            Severity::Alert,
            Signal::MissingFileRecords,
            format!("Volume {}: Strata read {} of about {} file records", v.index, count(read), count(room)),
            "The master file table has room for many more records than the index holds. Records were damaged or Strata \
             failed to read them, so files are missing from every list. The raw scan still covered the whole volume.",
        )
        .on(v.index)
        .figure("MFT size", bytes(v.file_table.map_or(0, |t| t.bytes)))
        .figure("Records it holds", count(room))
        .figure("Entries indexed", count(read))
        .bearing(Bearing::Unreadable)
    })
}

/// Live files cover almost none of a big volume.
fn sparse(disk: &DiskInputs, v: &VolumeInputs, missing: bool) -> Observation {
    let formatted = v.file_table.and_then(|t| t.created);
    let (bearing, why) = if missing {
        (Bearing::Unreadable, "The MFT has room for far more records than were read: Strata most likely failed to read it.".to_string())
    } else if older_data(disk) {
        let when = formatted.map(|t| format!(" on {}", day(t))).unwrap_or_default();
        (
            Bearing::Wiped(formatted),
            format!(
                "Deleted entries or findings outside files show that older data lies underneath: the volume was most \
                 likely formatted or wiped{when} and barely written to since."
            ),
        )
    } else {
        (Bearing::LittleUse, "Nothing points to older data underneath: the volume may simply have been left almost unused.".to_string())
    };
    let mut o = Observation::new(
        Severity::Alert,
        Signal::SparseFileTable,
        format!("File table covers {} of volume {}", percent(v.live.bytes, v.len), v.index),
        format!(
            "Volume {} is {} of {}, but the file index lists only {} files ({}). Either {} is damaged, the disk was \
             quick-formatted, or Strata failed to read it. {why}",
            v.index,
            bytes(v.len),
            v.fs,
            count(v.live.files),
            bytes(v.live.bytes),
            table_name(v)
        ),
    )
    .on(v.index)
    .figure("Volume size", bytes(v.len))
    .figure("Live files", count(v.live.files))
    .figure("Live data", bytes(v.live.bytes))
    .figure("Coverage", percent(v.live.bytes, v.len))
    .bearing(bearing);
    if let Some(t) = v.file_table {
        o = o.figure("MFT records", count(t.records()));
    }
    o
}

/// `the MFT` on NTFS, `the file table` elsewhere.
fn table_name(v: &VolumeInputs) -> &'static str {
    if v.file_table.is_some() || v.fs == "NTFS" { "the MFT" } else { "the file table" }
}
