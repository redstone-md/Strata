use super::testimg::{CS, Dir, ExfatImage, deleted, file_set};
use crate::testutil::{mem, noise};
use crate::{EntryState, FileEntry, FileId, FileSystem, open_filesystem};
use strata_volume::FsKind;

fn open(bytes: Vec<u8>) -> Box<dyn FileSystem> {
    open_filesystem(mem(bytes), FsKind::ExFat).expect("parse")
}

fn find<'a>(fs: &'a dyn FileSystem, path: &str) -> (FileId, &'a FileEntry) {
    let (i, e) = fs.entries().iter().enumerate().find(|(_, e)| e.path == path).unwrap_or_else(|| {
        let all: Vec<&str> = fs.entries().iter().map(|e| e.path.as_str()).collect();
        panic!("{path} not in {all:?}")
    });
    (FileId::new(i), e)
}

fn read_all(fs: &dyn FileSystem, id: FileId) -> Vec<u8> {
    let mut buf = vec![0u8; fs.entry(id).unwrap().size as usize];
    let n = fs.read(id, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed)).collect()
}

/// Root: chained file, fragmented file, `NoFatChain` file, a subdirectory with one file.
fn populate(img: &mut ExfatImage) {
    img.chain(&[10, 11]);
    img.write_clusters(&[10, 11], &pattern(900, 1));
    img.add(Dir::Root, &file_set("Read Me.txt", 0x20, 10, 900, false));
    img.chain(&[20, 25, 21]);
    img.write_clusters(&[20, 25, 21], &pattern(1400, 2));
    img.add(Dir::Root, &file_set("fragmented wallet backup.bin", 0x20, 20, 1400, false));
    img.allocate(&[30, 31, 32]);
    img.write_clusters(&[30, 31, 32], &pattern(1300, 3));
    img.add(Dir::Root, &file_set("contig.dat", 0x20, 30, 1300, true));
    img.allocate(&[40]);
    img.add(Dir::Root, &file_set("Docs", 0x10, 40, CS as u64, true));
    img.chain(&[41]);
    img.write_clusters(&[41], b"note");
    img.add(Dir::Cluster(40), &file_set("note.txt", 0x20, 41, 4, false));
}

#[test]
fn live_files_chains_and_contiguous_streams() {
    let mut img = ExfatImage::new();
    populate(&mut img);
    let fs = open(img.finish());
    assert_eq!(fs.kind(), FsKind::ExFat);
    assert_eq!(fs.label(), Some("WALLY"));
    let (id, e) = find(fs.as_ref(), "Read Me.txt");
    assert_eq!((e.size, e.state), (900, EntryState::Allocated));
    assert_eq!(read_all(fs.as_ref(), id), pattern(900, 1));
    assert_eq!(e.times.created.unwrap().to_string(), "2019-03-07 14:20:30");
    // Modified carries +0.5 s and a UTC+2 offset.
    let modified = e.times.modified.unwrap();
    assert_eq!((modified.to_string().as_str(), modified.unix_micros() % 1_000_000), ("2019-03-07 12:20:30", 500_000));
    let (id, e) = find(fs.as_ref(), "fragmented wallet backup.bin");
    assert_eq!(e.extents.len(), 3);
    assert_eq!(read_all(fs.as_ref(), id), pattern(1400, 2));
    let (id, e) = find(fs.as_ref(), "contig.dat");
    assert_eq!(e.extents.len(), 1);
    assert_eq!(read_all(fs.as_ref(), id), pattern(1300, 3));
    let (docs, d) = find(fs.as_ref(), "Docs");
    assert!(d.is_dir);
    let (note, n) = find(fs.as_ref(), "Docs/note.txt");
    assert_eq!(n.parent, Some(docs));
    assert_eq!(fs.children(docs), vec![note]);
    assert_eq!(read_all(fs.as_ref(), note), b"note");
    assert!(fs.entries().iter().all(|e| e.damage.is_empty()), "{:?}", fs.entries());
    assert!(fs.damage().is_empty(), "{:?}", fs.damage());
    let free = fs.unallocated();
    let vol = |c: u32| ExfatImage::cluster_offset(c) as u64;
    assert!(free.iter().any(|r| r.contains(vol(50))));
    assert!(!free.iter().any(|r| r.contains(vol(31)) || r.contains(vol(25)) || r.contains(vol(4))));
}

#[test]
fn deleted_sets_are_recovered_contiguously() {
    let mut img = ExfatImage::new();
    populate(&mut img);
    img.write_clusters(&[50, 51, 52], &pattern(1200, 4));
    img.add(Dir::Root, &deleted(file_set("old wallet.dat", 0x20, 50, 1200, false)));
    // Its clusters now belong to "Read Me.txt".
    img.add(Dir::Root, &deleted(file_set("overwritten.txt", 0x20, 10, 700, true)));
    let fs = open(img.finish());
    let (id, e) = find(fs.as_ref(), "old wallet.dat");
    assert_eq!(e.state, EntryState::Deleted);
    assert!(e.damage.is_empty(), "{:?}", e.damage);
    assert_eq!(read_all(fs.as_ref(), id), pattern(1200, 4));
    let (_, old) = find(fs.as_ref(), "overwritten.txt");
    assert!(old.damage.iter().any(|d| d.note().contains("overwritten")));
}

#[test]
fn deleted_directories_are_walked() {
    let mut img = ExfatImage::new();
    populate(&mut img);
    img.add(Dir::Root, &deleted(file_set("Old Stuff", 0x10, 60, CS as u64, true)));
    img.write_clusters(&[61], b"inner data");
    img.add(Dir::Cluster(60), &file_set("inner.txt", 0x20, 61, 10, true));
    // A deleted directory whose cluster was reused is not trusted.
    img.add(Dir::Root, &deleted(file_set("Gone", 0x10, 11, CS as u64, true)));
    let fs = open(img.finish());
    let (dir, d) = find(fs.as_ref(), "Old Stuff");
    assert!(d.is_dir && d.state == EntryState::Deleted);
    let (id, e) = find(fs.as_ref(), "Old Stuff/inner.txt");
    assert_eq!((e.state, e.parent), (EntryState::Deleted, Some(dir)));
    assert_eq!(read_all(fs.as_ref(), id), b"inner data");
    assert!(find(fs.as_ref(), "Gone").1.damage.iter().any(|d| d.note().contains("overwritten")));
}

#[test]
fn bad_set_checksum_and_cut_sets_are_damage() {
    let mut img = ExfatImage::new();
    let mut set = file_set("tampered.txt", 0x20, 0, 0, false);
    set[2][2] ^= 0x01;
    img.add(Dir::Root, &set);
    // A deleted set whose name entry was reused by a later (unrelated) primary entry.
    let mut cut = deleted(file_set("partly.txt", 0x20, 0, 0, false));
    cut[2][0] = 0x85;
    img.add(Dir::Root, &cut[..2]);
    let fs = open(img.finish());
    let (_, e) = find(fs.as_ref(), "uampered.txt");
    assert!(e.damage.iter().any(|d| d.note().contains("checksum")), "{:?}", e.damage);
    let cut = fs.entries().iter().find(|e| e.state == EntryState::Deleted).expect("cut set listed");
    assert!(cut.damage.iter().any(|d| d.note().contains("incomplete")), "{:?}", cut.damage);
}

#[test]
fn boot_region_checksums_and_backup() {
    let mut img = ExfatImage::new();
    populate(&mut img);
    let good = img.finish();
    let mut bad_backup = good.clone();
    bad_backup[13 * 512 + 7] ^= 0xFF;
    let fs = open(bad_backup);
    assert!(fs.damage().iter().any(|d| d.note().contains("backup boot region checksum")), "{:?}", fs.damage());
    assert!(!fs.damage().iter().any(|d| d.note().contains("main boot region")));
    let mut no_main = good.clone();
    no_main[..512].fill(0);
    let fs = open(no_main);
    assert!(fs.damage().iter().any(|d| d.note().contains("using backup")));
    assert!(fs.damage().iter().any(|d| d.note().contains("main boot region checksum")));
    assert_eq!(read_all(fs.as_ref(), find(fs.as_ref(), "Read Me.txt").0), pattern(900, 1));
}

#[test]
fn hostile_input_never_panics() {
    assert!(open_filesystem(mem(vec![0u8; 1 << 20]), FsKind::ExFat).is_err());
    assert!(open_filesystem(mem(Vec::new()), FsKind::ExFat).is_err());
    let mut good = ExfatImage::new();
    populate(&mut good);
    let good = good.finish();
    // Absurd geometry must not be read or allocated.
    let mut huge = good.clone();
    huge[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
    huge[84..88].copy_from_slice(&u32::MAX.to_le_bytes());
    huge[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
    let _ = open_filesystem(mem(huge), FsKind::ExFat);
    for cut in [100, 512, 5000, 12_000, 20_000, 60_000] {
        let _ = open_filesystem(mem(good[..cut].to_vec()), FsKind::ExFat);
    }
    for seed in 1..40u64 {
        let _ = open_filesystem(mem(noise(256 << 10, seed)), FsKind::ExFat);
        // Valid boot sector, garbage everywhere else.
        let mut img = good.clone();
        let junk = noise(img.len() - 512, seed);
        img[512..].copy_from_slice(&junk);
        let _ = open_filesystem(mem(img), FsKind::ExFat);
        // Valid metadata, garbage directory clusters.
        let mut img = good.clone();
        let root = ExfatImage::cluster_offset(4) + 96;
        let junk = noise(img.len() - root, seed);
        img[root..].copy_from_slice(&junk);
        if let Ok(fs) = open_filesystem(mem(img), FsKind::ExFat) {
            for i in 0..fs.entries().len() {
                let mut buf = [0u8; 64];
                let _ = fs.read(FileId::new(i), 0, &mut buf);
            }
        }
    }
}
