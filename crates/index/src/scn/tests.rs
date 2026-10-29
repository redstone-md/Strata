//! End-to-end decoding of synthetic scan files built with the decoded structure.

use super::testkit::{FileTypeEntry, ObjectBuilder, ScnWriter, fat_record, ntfs_record};
use super::*;
use crate::index::DiskIndex;
use crate::record::{BlockClass, TextKind};
use crate::side::EntrySource;
use strata_identify::TypeId;

const DISK: u64 = 64 << 30;
const P1: u64 = 0x10_0000;
const P1_LEN: u64 = 20 << 30;
const P2: u64 = P1 + P1_LEN;

/// A host disk (id 2) with its own partition, the scanned disk (id 5) with two partitions
/// and one nested object, progress marks, boot elements and a file-type stream.
fn synthetic() -> Vec<u8> {
    let mut w = ScnWriter::new();
    w.object(&ObjectBuilder::new(1).name("This computer").finish(), false);
    w.object(&ObjectBuilder::new(2).parent(1).disk(4 << 40, 512).name("host disk").finish(), false);
    w.object(&ObjectBuilder::new(3).parent(2).partition(0x10_0000, 3 << 40, 7).fs_name("NTFS").finish(), false);
    w.object(&ObjectBuilder::new(5).disk(DISK, 512).name("evidence disk").finish(), true);
    w.object(&ObjectBuilder::new(6).parent(5).partition(P1, P1_LEN, 7).fs_name("NTFS").finish(), false);
    w.object(&ObjectBuilder::new(7).parent(5).partition(P2, 10 << 30, 0x0B).fs_name("FAT32").finish(), false);
    w.object(&ObjectBuilder::new(8).parent(7).partition(0x8000, 1 << 20, 0).finish(), false);
    w.object(&ObjectBuilder::new(9).parent(5).partition(DISK - 512, 4096, 0).finish(), false);
    w.progress(1 << 30);
    w.element(3, *b"TN", &[ntfs_record(P1, P1_LEN - 512, 512), ntfs_record(P1 + P1_LEN - 512, P1_LEN - 512, 512)].concat());
    w.progress(30 << 30);
    w.element(3, *b"AF", &[fat_record(32, P2), fat_record(16, 40 << 30)].concat());
    w.element(10, *b"TN", &[0u8; 28]);
    let entries = [
        FileTypeEntry::new(0x2000, 0x8000, *b"\0JPG").details(0x02, None),
        FileTypeEntry::new(0x2100, 300 << 10, *b"TXTA"),
        FileTypeEntry::new(0x2100 + 100, 10, *b"TXTA"),
        FileTypeEntry::new(0x9000, 4096, *b"\0RAR"),
        FileTypeEntry::new(0x0100_0000, 1 << 20, *b"PEDL").details(0x11, Some("lib.dll")),
    ];
    w.file_types(&entries, 7);
    w.progress(DISK);
    w.finish()
}

#[test]
fn decodes_metadata_and_volumes_of_the_scanned_device_only() {
    let info = ScnFile::parse(&synthetic()).unwrap();
    assert!(info.damage.is_empty(), "{:?}", info.damage);
    let m = &info.metadata;
    assert_eq!((m.version, m.disk_len, m.sector_size, m.scanned_to), (1, Some(DISK), Some(512), Some(DISK)));
    assert_eq!(m.device_name.as_deref(), Some("evidence disk"));
    assert_eq!(m.groups.get("OOGR"), Some(&3));
    assert_eq!(m.undecoded, vec!["TN/10".to_string()]);
    assert_eq!(m.file_type_entries, 5);
    let objects: Vec<_> = info.recognized_volumes.iter().filter(|v| v.origin == ScnVolumeOrigin::PartitionObject).collect();
    let ranges: Vec<_> = objects.iter().map(|v| (v.range.start(), v.range.len(), v.fs)).collect();
    assert_eq!(
        ranges,
        vec![(P1, P1_LEN, FsKind::Ntfs), (P2, 10 << 30, FsKind::Fat32), (P2 + 0x8000, 1 << 20, FsKind::Unknown)],
        "host partition and the object running past the disk end are ignored; nested starts are relative"
    );
}

#[test]
fn boot_records_add_candidates_not_covered_by_partitions() {
    let info = ScnFile::parse(&synthetic()).unwrap();
    assert_eq!(info.boot_records.len(), 3 + 2);
    let extra: Vec<_> = info.recognized_volumes.iter().filter(|v| v.origin != ScnVolumeOrigin::PartitionObject).collect();
    let starts: Vec<_> = extra.iter().map(|v| (v.range.start(), v.fs)).collect();
    assert_eq!(starts, vec![(P1 + P1_LEN - 512, FsKind::Ntfs), (40 << 30, FsKind::Fat16)], "backup reading at P1 is already a partition");
}

#[test]
fn file_type_stream_spanning_groups_is_decoded() {
    let info = ScnFile::parse(&synthetic()).unwrap();
    let tags: Vec<String> = info.signature_regions.iter().map(|r| r.tag_name()).collect();
    assert_eq!(tags, ["JPG", "TXTA", "RAR", "PEDL"]);
    assert_eq!(info.signature_regions[0].offset, 0x2000 * 512);
    assert_eq!(info.signature_regions[1].len, 300 << 10, "the second text piece lies inside the first");
}

#[test]
fn seeds_an_index_with_hints() {
    let info = ScnFile::parse(&synthetic()).unwrap();
    let mut idx = DiskIndex::new(DISK, 64 << 10);
    info.seed(&mut idx, "R-Studio scan: synthetic.scn");
    let jpg = idx.record_at(0x2000 * 512).unwrap();
    assert!(jpg.has_signature());
    let sigs: Vec<_> = idx.signatures().iter().map(|h| (h.type_id, h.source, h.declared_len)).collect();
    assert_eq!(sigs, vec![(TypeId::Jpeg, EntrySource::RStudio, Some(0x8000)), (TypeId::Dll, EntrySource::RStudio, Some(1 << 20))]);
    assert!(idx.record_at(0x9000 * 512).unwrap().has_signature(), "unmapped tags still flag the block");
    let text = idx.text_ranges();
    assert_eq!(text.len(), 1);
    let r = idx.record_at(text[0].start()).unwrap();
    assert_eq!((r.class(), r.text_kind(), r.is_seeded()), (BlockClass::Text, Some(TextKind::Ascii), true));
    assert!(text[0].start() >= 0x2100 * 512 && text[0].end() <= 0x2100 * 512 + (300 << 10));
    assert_eq!(idx.boot_records().len(), 5);
    assert_eq!(idx.provenance().external_scanned_to, Some(DISK));
    info.seed(&mut idx, "R-Studio scan: synthetic.scn");
    assert_eq!(idx.provenance().seeded_from.len(), 1);
    assert_eq!(idx.signatures().len(), 2, "seeding twice adds nothing");
}

#[test]
fn damaged_files_still_yield_what_is_intact() {
    let mut bytes = synthetic();
    let len = bytes.len();
    bytes[len - 40] ^= 0x55;
    let info = ScnFile::parse(&bytes).unwrap();
    assert!(!info.damage.is_empty());
    assert_eq!(info.metadata.disk_len, Some(DISK));
    assert!(ScnFile::parse(&bytes[..100]).is_err());
}

#[test]
fn finds_the_scan_file_beside_an_image() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk one.rdr");
    std::fs::write(&image, b"x").unwrap();
    assert!(ScnFile::beside(&image).is_none());
    std::fs::write(dir.path().join("disk one.scn"), synthetic()).unwrap();
    assert_eq!(ScnFile::beside(&image), Some(dir.path().join("disk one.scn")));
    assert!(ScnFile::open(&dir.path().join("disk one.scn")).is_ok());
}
