//! The disk index end to end on synthetic images: built by the deep scan, used by carving
//! (same result as carving's own pass), shown in the sector map, and seeded from an
//! R-Studio scan file found next to the image.

use strata_identify::testkit;
use strata_index::scn::testkit::{FileTypeEntry, ObjectBuilder, ScnWriter};
use strata_workbench::{BlockClass, HitQuery, JobKind, JobState, Workbench};

const MIB: usize = 1 << 20;

/// A volume-less disk: files in "free space", text, noise and zero runs.
fn image() -> Vec<u8> {
    let mut disk = vec![0u8; 6 * MIB];
    let zip = testkit::zip(&[("notes.txt", b"hello there", false), ("b.bin", &[7u8; 3000], true)]);
    disk[0x10000..0x10000 + zip.len()].copy_from_slice(&zip);
    let gz = testkit::gzip("log.txt", &b"line of text\n".repeat(400));
    disk[2 * MIB..2 * MIB + gz.len()].copy_from_slice(&gz);
    for (i, b) in disk[3 * MIB..3 * MIB + 768 * 1024].iter_mut().enumerate() {
        *b = b"plain words for the text detector. "[i % 35];
    }
    let mut x = 0x1234_5678u32;
    for b in &mut disk[4 * MIB..5 * MIB] {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
    disk
}

fn carved(wb: &Workbench) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = wb
        .hits(&HitQuery::default())
        .unwrap()
        .into_iter()
        .filter(|h| h.hit.detector == "carve.unallocated")
        .map(|h| (h.hit.offset, h.hit.value))
        .collect();
    out.sort();
    out
}

#[test]
fn carving_from_the_index_matches_carving_with_its_own_pass() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    std::fs::write(&img, image()).unwrap();

    let indexed = Workbench::open(&dir.path().join("a.strata")).unwrap();
    let id = indexed.add_evidence(&img.display().to_string()).unwrap().id;
    assert!(indexed.disk_index(id, 10).is_none(), "no index before the scan");
    assert!(matches!(indexed.run_step(JobKind::Scan, id).unwrap().state, JobState::Done(_)));
    let view = indexed.disk_index(id, 6).expect("scan builds the index");
    assert_eq!(view.stats.scanned_to, (6 * MIB) as u64);
    assert!(view.stats.signature_hits >= 2, "{:?}", view.stats);
    let carve = indexed.run_step(JobKind::Carve, id).unwrap();
    assert!(matches!(carve.state, JobState::Done(_)));
    let indexed_read = carve.progress.read_bytes;

    let plain = Workbench::open(&dir.path().join("b.strata")).unwrap();
    let id2 = plain.add_evidence(&img.display().to_string()).unwrap().id;
    let carve = plain.run_step(JobKind::Carve, id2).unwrap();
    assert!(matches!(carve.state, JobState::Done(_)));
    // Both read the carved files themselves; only the run without an index reads the free
    // space for file starts.
    assert_eq!(carve.progress.read_bytes, indexed_read + (6 * MIB) as u64, "{:?}", carve.progress);

    let from_index = carved(&indexed);
    assert!(from_index.len() >= 2, "{from_index:?}");
    assert_eq!(from_index, carved(&plain));
}

#[test]
fn sector_map_and_view_show_content_classes() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    std::fs::write(&img, image()).unwrap();
    let wb = Workbench::open(&dir.path().join("c.strata")).unwrap();
    let id = wb.add_evidence(&img.display().to_string()).unwrap().id;
    assert!(wb.sector_map(id, 6).unwrap().cells.iter().all(|c| c.content.is_none()));
    wb.run_step(JobKind::Scan, id).unwrap();
    let map = wb.sector_map(id, 6).unwrap();
    let content: Vec<_> = map.cells.iter().map(|c| c.content).collect();
    assert_eq!(content[1], Some(BlockClass::Zero));
    assert_eq!(content[3], Some(BlockClass::Text));
    assert_eq!(content[4], Some(BlockClass::Random));
    let view = wb.disk_index(id, 6).unwrap();
    assert_eq!(view.runs.iter().map(|r| r.1).sum::<u32>(), 6);
    let ranges = wb.interesting_ranges(id).unwrap();
    let interesting: u64 = ranges.iter().map(|r| r.len()).sum();
    assert!(interesting < (4 * MIB) as u64, "zero blocks are skipped: {ranges:?}");
    assert!(ranges.iter().any(|r| r.contains((4 * MIB) as u64)));
    assert_eq!(view.stats.by_class[BlockClass::Text as usize], 12);
}

/// An NTFS boot sector at an offset no partition table or 1 MiB sweep finds.
fn ntfs_boot(total_sectors: u64) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    s[3..11].copy_from_slice(b"NTFS    ");
    s[11..13].copy_from_slice(&512u16.to_le_bytes());
    s[0x28..0x30].copy_from_slice(&total_sectors.to_le_bytes());
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
    s
}

#[test]
fn scan_file_beside_the_image_seeds_volumes_and_index() {
    const HIDDEN: u64 = 0x18_0000;
    let dir = tempfile::tempdir().unwrap();
    let mut disk = image();
    disk[HIDDEN as usize..HIDDEN as usize + 512].copy_from_slice(&ntfs_boot(2047));
    let img = dir.path().join("disk.img");
    std::fs::write(&img, &disk).unwrap();

    let mut w = ScnWriter::new();
    w.object(&ObjectBuilder::new(4).disk(disk.len() as u64, 512).name("evidence").finish(), true);
    w.object(&ObjectBuilder::new(5).parent(4).partition(HIDDEN, 2048 * 512, 7).fs_name("NTFS").finish(), false);
    w.object(&ObjectBuilder::new(6).parent(4).partition(0x30_0000, MIB as u64, 7).fs_name("NTFS").finish(), false);
    w.file_types(&[FileTypeEntry::new(0x10000 / 512, 4096, *b"\0ZIP"), FileTypeEntry::new(3 * MIB as u64 / 512, 256 * 1024, *b"TXTA")], 5);
    w.progress(disk.len() as u64);
    std::fs::write(dir.path().join("disk.scn"), w.finish()).unwrap();

    let wb = Workbench::open(&dir.path().join("d.strata")).unwrap();
    let record = wb.add_evidence(&img.display().to_string()).unwrap();
    let imported: Vec<_> = record.volumes.iter().filter(|v| format!("{:?}", v.origin) == "RStudioScan").collect();
    assert_eq!(imported.len(), 1, "only the candidate with a real boot sector: {:?}", record.volumes);
    assert_eq!((imported[0].range.start(), imported[0].range.len()), (HIDDEN, 2048 * 512));

    let view = wb.disk_index(record.id, 6).expect("seeded before any scan");
    assert_eq!(view.provenance.seeded_from, vec!["R-Studio scan: disk.scn".to_string()]);
    assert_eq!(view.stats.scanned_to, 0);
    assert_eq!(view.stats.signature_hits, 1);
    assert_eq!(view.stats.seeded, 4);
    // Our own pass refines the seeded blocks and keeps the imported hint.
    wb.run_step(JobKind::Scan, record.id).unwrap();
    let view = wb.disk_index(record.id, 6).unwrap();
    assert_eq!(view.stats.seeded, 0);
    assert_eq!(view.stats.scanned_to, disk.len() as u64);
}
