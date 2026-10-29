use super::testimg::*;
use crate::testutil::{mem, noise};
use crate::{EntryState, FileEntry, FileId, FileSystem, open_filesystem};
use strata_volume::FsKind;

fn open(bytes: Vec<u8>, kind: FsKind) -> Box<dyn FileSystem> {
    open_filesystem(mem(bytes), kind).expect("parse")
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
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn notes(e: &FileEntry) -> String {
    e.damage.iter().map(|d| d.note()).collect::<Vec<_>>().join("; ")
}

/// Root with lost+found and home/; home holds files of every mapping kind plus deleted names.
fn populate(img: &mut ExtImage, ext4: bool) {
    let dir_flags = if ext4 { EXTENTS_FL } else { 0 };
    let map = |b: usize| if ext4 { extents(&[(0, 1, b as u32)]) } else { block_ptrs(&[b as u32]) };
    let root = img.alloc(1, false);
    img.write(root, &dir_block(&[(2, ".", 2, false), (2, "..", 2, false), (11, "lost+found", 2, false), (12, "home", 2, false)]));
    img.set_inode(2, &inode(S_IFDIR, BS as u64, 4, dir_flags, map(root)), true);
    let lf = img.alloc(1, false);
    img.write(lf, &dir_block(&[(11, ".", 2, false), (2, "..", 2, false)]));
    img.set_inode(11, &inode(S_IFDIR, BS as u64, 2, dir_flags, map(lf)), true);

    let home = img.alloc(1, false);
    img.write(
        home,
        &dir_block(&[
            (12, ".", 2, false),
            (2, "..", 2, false),
            (13, "wallet.dat", 1, false),
            (17, "secret.key", 1, true),
            (14, "old.txt", 1, false),
            (18, "ext2del.txt", 1, true),
            (15, "inline.txt", 1, false),
            (16, "link", 7, false),
            (20, "big.bin", 1, false),
            (21, "deep.bin", 1, false),
        ]),
    );
    img.set_inode(12, &inode(S_IFDIR, BS as u64, 2, dir_flags, map(home)), true);

    // wallet.dat: 2500 bytes, two extents with a hole-free split.
    let w = img.alloc(3, false);
    img.write(w, &pattern(2500, 1));
    if ext4 {
        img.set_inode(13, &inode(S_IFREG, 2500, 1, EXTENTS_FL, extents(&[(0, 2, w as u32), (2, 1, (w + 2) as u32)])), true);
    } else {
        img.set_inode(13, &inode(S_IFREG, 2500, 1, 0, block_ptrs(&[w as u32, w as u32 + 1, w as u32 + 2])), true);
    }
    // old.txt: block map even on ext4.
    let o = img.alloc(2, false);
    img.write(o, &pattern(1500, 2));
    img.set_inode(14, &inode(S_IFREG, 1500, 1, 0, block_ptrs(&[o as u32, o as u32 + 1])), true);
    // inline.txt (ext4) or a tiny block file (ext2).
    if ext4 {
        img.set_inode(15, &inline_inode(S_IFREG, &pattern(80, 3)), true);
    } else {
        let b = img.alloc(1, false);
        img.write(b, &pattern(80, 3));
        img.set_inode(15, &inode(S_IFREG, 80, 1, 0, block_ptrs(&[b as u32])), true);
    }
    let mut target = [0u8; 60];
    target[..11].copy_from_slice(b"/etc/passwd");
    img.set_inode(16, &inode(S_IFLNK, 11, 1, 0, target), true);
    // secret.key: deleted, ext4 style (pointers wiped); its old blocks are free.
    let s = img.alloc(1, true);
    img.write(s, &pattern(700, 4));
    let secret = inode(S_IFREG, 700, 1, EXTENTS_FL, extents(&[(0, 1, s as u32)]));
    img.set_inode(17, &deleted(secret.clone(), true), false);
    // ext2del.txt: deleted, ext2 style (pointers survive).
    let d = img.alloc(1, true);
    img.write(d, &pattern(900, 5));
    img.set_inode(18, &deleted(inode(S_IFREG, 900, 1, 0, block_ptrs(&[d as u32])), false), false);
    // Orphan: in use, no name anywhere.
    let orphan = img.alloc(1, false);
    img.write(orphan, b"orphaned bytes");
    img.set_inode(19, &inode(S_IFREG, 14, 1, 0, block_ptrs(&[orphan as u32])), true);
    // big.bin: 14 blocks -> 12 direct + single indirect.
    let big = img.alloc(14, false);
    img.write(big, &pattern(14 * BS, 6));
    let ind = img.alloc(1, false);
    let ptrs: Vec<u8> = (12..14).flat_map(|i| ((big + i) as u32).to_le_bytes()).collect();
    img.write(ind, &ptrs);
    let mut direct: Vec<u32> = (0..12).map(|i| (big + i) as u32).collect();
    direct.extend([ind as u32, 0, 0]);
    img.set_inode(20, &inode(S_IFREG, (14 * BS) as u64, 1, 0, block_ptrs(&direct)), true);
    // deep.bin: extent tree of depth 1 (ext4) or plain block map.
    let deep = img.alloc(2, false);
    img.write(deep, &pattern(2 * BS, 7));
    if ext4 {
        let leaf = img.alloc(1, false);
        img.write(leaf, &extent_node::<BS>(&[(0, 2, deep as u32)], 0, 84));
        img.set_inode(21, &inode(S_IFREG, (2 * BS) as u64, 1, EXTENTS_FL, extent_node(&[(0, 0, leaf as u32)], 1, 4)), true);
    } else {
        img.set_inode(21, &inode(S_IFREG, (2 * BS) as u64, 1, 0, block_ptrs(&[deep as u32, deep as u32 + 1])), true);
    }
    if ext4 {
        img.add_journal(17, &secret);
    }
}

fn image(groups: usize, ext4: bool) -> Vec<u8> {
    let mut img = ExtImage::new(groups, ext4);
    populate(&mut img, ext4);
    img.finish()
}

#[test]
fn ext4_live_files_of_every_mapping_kind() {
    let fs = open(image(1, true), FsKind::Ext4);
    assert_eq!(fs.kind(), FsKind::Ext4);
    assert!(fs.damage().is_empty(), "{:?}", fs.damage());
    let (id, e) = find(fs.as_ref(), "home/wallet.dat");
    assert_eq!((e.size, e.state, e.native_id), (2500, EntryState::Allocated, 13));
    assert_eq!(read_all(fs.as_ref(), id), pattern(2500, 1));
    assert_eq!(e.times.modified.unwrap().to_string(), "2020-01-01 00:00:00");
    assert_eq!(e.times.created.unwrap().unix_micros() % 1_000_000, 500_000);
    let (id, _) = find(fs.as_ref(), "home/old.txt");
    assert_eq!(read_all(fs.as_ref(), id), pattern(1500, 2));
    let (id, e) = find(fs.as_ref(), "home/inline.txt");
    assert!(e.resident.is_some());
    assert_eq!(read_all(fs.as_ref(), id), pattern(80, 3));
    let (id, _) = find(fs.as_ref(), "home/link");
    assert_eq!(read_all(fs.as_ref(), id), b"/etc/passwd");
    let (id, _) = find(fs.as_ref(), "home/big.bin");
    assert_eq!(read_all(fs.as_ref(), id), pattern(14 * BS, 6));
    let (id, _) = find(fs.as_ref(), "home/deep.bin");
    assert_eq!(read_all(fs.as_ref(), id), pattern(2 * BS, 7));
    let (_, lf) = find(fs.as_ref(), "lost+found");
    assert!(lf.is_dir);
    let (home, _) = find(fs.as_ref(), "home");
    assert_eq!(fs.children(home).len(), 8);
}

#[test]
fn deleted_names_from_slack_and_journal_undelete() {
    let fs = open(image(1, true), FsKind::Ext4);
    let (id, e) = find(fs.as_ref(), "home/secret.key");
    assert_eq!(e.state, EntryState::Deleted);
    assert!(notes(e).contains("journal"), "{}", notes(e));
    assert_eq!(read_all(fs.as_ref(), id), pattern(700, 4));
    let (id, e) = find(fs.as_ref(), "home/ext2del.txt");
    assert_eq!((e.state, e.size), (EntryState::Deleted, 900));
    assert_eq!(read_all(fs.as_ref(), id), pattern(900, 5));
    let (id, e) = find(fs.as_ref(), "$Orphans/#19");
    assert_eq!(e.state, EntryState::Orphan);
    assert_eq!(read_all(fs.as_ref(), id), b"orphaned bytes");
}

#[test]
fn wiped_pointers_without_journal_are_reported() {
    let mut img = ExtImage::new(1, false);
    populate(&mut img, false);
    let s = inode(S_IFREG, 700, 1, EXTENTS_FL, extents(&[(0, 1, 40)]));
    img.set_inode(17, &deleted(s, true), false);
    let fs = open(img.finish(), FsKind::Ext2);
    assert_eq!(fs.kind(), FsKind::Ext2);
    let (_, e) = find(fs.as_ref(), "home/secret.key");
    assert_eq!((e.state, e.size), (EntryState::Deleted, 0));
    assert!(notes(e).contains("content pointers wiped (ext3/4 delete) on 2020-01-01 00:01:00"), "{}", notes(e));
    assert!(e.times.modified.is_some());
}

#[test]
fn ext2_tree_and_free_space() {
    let fs = open(image(1, false), FsKind::Ext2);
    let (id, _) = find(fs.as_ref(), "home/wallet.dat");
    assert_eq!(read_all(fs.as_ref(), id), pattern(2500, 1));
    let free = fs.unallocated();
    assert!(!free.is_empty());
    let (_, e) = find(fs.as_ref(), "home/wallet.dat");
    let used = e.extents[0].volume_offset.unwrap();
    assert!(free.iter().all(|r| !r.contains(used)));
    let (_, del) = find(fs.as_ref(), "home/ext2del.txt");
    assert!(free.iter().any(|r| r.contains(del.extents[0].volume_offset.unwrap())));
}

#[test]
fn damaged_primary_superblock_falls_back_to_backup() {
    let mut img = ExtImage::new(2, true);
    populate(&mut img, true);
    img.corrupt_primary_superblock();
    let fs = crate::ext::open(mem(img.finish())).expect("parse via backup");
    assert!(fs.damage().iter().any(|d| d.note().contains("backup superblock from group 1")), "{:?}", fs.damage());
    let (id, _) = find(&fs, "home/wallet.dat");
    assert_eq!(read_all(&fs, id), pattern(2500, 1));
}

#[test]
fn garbage_and_truncated_images_never_panic() {
    for seed in 0..24u64 {
        let _ = crate::ext::open(mem(noise(64 << 10, seed)));
    }
    let good = image(1, true);
    for cut in [0, 1500, 2048, 3 << 10, 6 << 10, 20 << 10, 40 << 10, 100 << 10] {
        let _ = crate::ext::open(mem(good[..cut.min(good.len())].to_vec()));
    }
    // Scribble over the metadata blocks (descriptors, bitmaps, inode table, directories).
    for seed in 0..48u64 {
        let mut bad = good.clone();
        let junk = noise(512, seed);
        let at = 2048 + (seed as usize * 997) % (60 << 10);
        bad[at..at + 512].copy_from_slice(&junk);
        if let Ok(fs) = crate::ext::open(mem(bad)) {
            for (i, e) in fs.entries().iter().enumerate() {
                let mut buf = vec![0u8; (e.size as usize).min(1 << 16)];
                let _ = fs.read(FileId::new(i), 0, &mut buf);
            }
        }
    }
}
