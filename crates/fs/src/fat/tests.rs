use super::testimg::{CS, Dir, FatImage, deleted, dots, short, with_lfn};
use crate::testutil::{mem, noise};
use crate::{EntryState, FileEntry, FileId, FileSystem, open_filesystem};
use strata_volume::FsKind;

fn open(bytes: Vec<u8>) -> Box<dyn FileSystem> {
    open_filesystem(mem(bytes), FsKind::Fat16).expect("parse")
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
    (0..len).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

/// Root: long-named file, fragmented file, a subdirectory with one file.
fn populate(img: &mut FatImage) {
    img.chain(&[10, 11]);
    img.write_clusters(&[10, 11], &pattern(1000, 1));
    img.add(Dir::Root, &with_lfn("Read Me Please.txt", short(b"README~1TXT", 0x20, 10, 1000)));
    img.chain(&[20, 25, 21]);
    img.write_clusters(&[20, 25, 21], &pattern(1400, 2));
    img.add(Dir::Root, &[short(b"FRAG    BIN", 0x20, 20, 1400)]);
    img.chain(&[30]);
    img.add(Dir::Root, &[short(b"DOCS       ", 0x10, 30, 0)]);
    img.add(Dir::Cluster(30), &dots(30, 0));
    img.chain(&[31]);
    img.write_clusters(&[31], b"note");
    let mut note = short(b"NOTE    TXT", 0x20, 31, 4);
    note[12] = 0x18;
    img.add(Dir::Cluster(30), &[note]);
}

#[test]
fn live_files_long_names_and_fragmented_chains() {
    for (mut img, kind) in [(FatImage::fat16(), FsKind::Fat16), (FatImage::fat32(), FsKind::Fat32), (FatImage::fat12(), FsKind::Fat12)] {
        populate(&mut img);
        let fs = open(img.finish());
        assert_eq!(fs.kind(), kind);
        let (id, e) = find(fs.as_ref(), "Read Me Please.txt");
        assert_eq!((e.size, e.state), (1000, EntryState::Allocated));
        assert_eq!(e.times.modified.unwrap().to_string(), "2012-01-15 10:30:20");
        assert_eq!(read_all(fs.as_ref(), id), pattern(1000, 1));
        let (id, e) = find(fs.as_ref(), "FRAG.BIN");
        assert_eq!(e.extents.len(), 3, "{kind:?}");
        assert_eq!(read_all(fs.as_ref(), id), pattern(1400, 2));
        let (docs, _) = find(fs.as_ref(), "DOCS");
        let (note, n) = find(fs.as_ref(), "DOCS/note.txt");
        assert_eq!(n.parent, Some(docs));
        assert_eq!(fs.children(docs), vec![note]);
        assert_eq!(read_all(fs.as_ref(), note), b"note");
        assert!(fs.entries().iter().all(|e| e.damage.is_empty()), "{kind:?}");
        assert!(fs.damage().is_empty());
    }
}

#[test]
fn deleted_files_are_recovered_contiguously() {
    let mut img = FatImage::fat16();
    populate(&mut img);
    img.write_clusters(&[40, 41, 42], &pattern(1200, 3));
    img.add(Dir::Root, &deleted(with_lfn("secret wallet.dat", short(b"SECRET~1DAT", 0x20, 40, 1200))));
    img.add(Dir::Root, &deleted(vec![short(b"ONE     TXT", 0x20, 50, 10)]));
    // Its clusters now belong to READ ME.
    img.add(Dir::Root, &deleted(vec![short(b"OLD     TXT", 0x20, 10, 600)]));
    let fs = open(img.finish());
    let (id, e) = find(fs.as_ref(), "secret wallet.dat");
    assert_eq!(e.state, EntryState::Deleted);
    assert!(e.damage.is_empty(), "{:?}", e.damage);
    assert_eq!(read_all(fs.as_ref(), id), pattern(1200, 3));
    assert_eq!(find(fs.as_ref(), "_NE.TXT").1.state, EntryState::Deleted);
    let (_, old) = find(fs.as_ref(), "_LD.TXT");
    assert!(old.damage.iter().any(|d| d.note().contains("overwritten")));
    let free = fs.unallocated();
    let vol = |c: u32| -> u64 {
        let data_start = (1 + 2 * 32) * 512 + 64 * 32;
        (data_start + (c as usize - 2) * CS) as u64
    };
    assert!(free.iter().any(|r| r.contains(vol(40))));
    assert!(!free.iter().any(|r| r.contains(vol(10))));
}

#[test]
fn deleted_directories_are_walked() {
    let mut img = FatImage::fat16();
    populate(&mut img);
    img.add(Dir::Root, &deleted(with_lfn("Old Stuff", short(b"OLDSTU~1   ", 0x10, 60, 0))));
    img.add(Dir::Cluster(60), &dots(60, 0));
    img.write_clusters(&[61], b"inner data");
    img.add(Dir::Cluster(60), &deleted(vec![short(b"A       TXT", 0x20, 61, 10)]));
    img.add(Dir::Cluster(60), &[short(b"B       TXT", 0x20, 62, 0)]);
    // A deleted directory whose cluster was reused is not trusted.
    img.add(Dir::Root, &deleted(vec![short(b"GONE       ", 0x10, 11, 0)]));
    let fs = open(img.finish());
    let (dir, d) = find(fs.as_ref(), "Old Stuff");
    assert!(d.is_dir && d.state == EntryState::Deleted);
    let (a, e) = find(fs.as_ref(), "Old Stuff/_.TXT");
    assert_eq!((e.state, e.parent), (EntryState::Deleted, Some(dir)));
    assert_eq!(read_all(fs.as_ref(), a), b"inner data");
    assert_eq!(find(fs.as_ref(), "Old Stuff/B.TXT").1.state, EntryState::Deleted);
    assert!(find(fs.as_ref(), "_ONE").1.damage.iter().any(|d| d.note().contains("overwritten")));
}

#[test]
fn bad_lfn_checksum_falls_back_to_short_name() {
    let mut img = FatImage::fat16();
    let mut slots = with_lfn("Pretty Name.txt", short(b"PRETTY~1TXT", 0x20, 0, 0));
    slots[0][13] ^= 0x55;
    img.add(Dir::Root, &slots);
    let fs = open(img.finish());
    let (_, e) = find(fs.as_ref(), "PRETTY~1.TXT");
    assert!(e.damage.iter().any(|d| d.note().contains("long name")));
}

#[test]
fn damaged_fat_copy_uses_backup_and_loops_stop() {
    let mut img = FatImage::fat16();
    populate(&mut img);
    img.set_fat_copy(0, 25, 0xFFF0);
    img.chain(&[70, 71]);
    img.set_fat(71, 70);
    img.add(Dir::Root, &[short(b"LOOP    BIN", 0x20, 70, 100_000)]);
    let fs = open(img.finish());
    let (id, _) = find(fs.as_ref(), "FRAG.BIN");
    assert_eq!(read_all(fs.as_ref(), id), pattern(1400, 2));
    assert!(fs.damage().iter().any(|d| d.note().contains("restored from copy 2")), "{:?}", fs.damage());
    let (_, l) = find(fs.as_ref(), "LOOP.BIN");
    assert!(l.damage.iter().any(|d| d.note().contains("loops")));
    assert_eq!(l.extents.iter().map(|x| x.len).sum::<u64>(), 2 * CS as u64);
}

#[test]
fn directory_loops_terminate() {
    let mut img = FatImage::fat16();
    img.chain(&[30]);
    img.add(Dir::Root, &[short(b"A          ", 0x10, 30, 0)]);
    img.add(Dir::Cluster(30), &dots(30, 0));
    img.add(Dir::Cluster(30), &[short(b"SELF       ", 0x10, 30, 0), short(b"UP         ", 0x10, 0, 0)]);
    let fs = open(img.finish());
    assert!(fs.entries().len() < 10);
}

#[test]
fn hostile_input_never_panics() {
    assert!(open_filesystem(mem(vec![0u8; 1 << 20]), FsKind::Fat32).is_err());
    assert!(open_filesystem(mem(Vec::new()), FsKind::Fat12).is_err());
    let mut good = FatImage::fat16();
    populate(&mut good);
    let good = good.finish();
    for cut in [100, 512, 5000, 40_000, 100_000] {
        let _ = open_filesystem(mem(good[..cut].to_vec()), FsKind::Fat16);
    }
    for seed in 1..40u64 {
        let _ = open_filesystem(mem(noise(512 << 10, seed)), FsKind::Fat32);
        // Valid BPB, garbage FAT and directories.
        let mut img = good.clone();
        let junk = noise(img.len() - 512, seed);
        img[512..].copy_from_slice(&junk);
        if let Ok(fs) = open_filesystem(mem(img), FsKind::Fat16) {
            for i in 0..fs.entries().len() {
                let mut buf = [0u8; 64];
                let _ = fs.read(FileId::new(i), 0, &mut buf);
            }
        }
    }
}
