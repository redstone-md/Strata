use super::testimg::{CS, FT, NtfsImage, RS, RecordBuilder, fref};
use crate::testutil::{mem, noise};
use crate::{EntryState, FileEntry, FileId, FileSystem, FsOptions, open_filesystem, open_filesystem_with};
use strata_kernel::Timestamp;
use strata_volume::FsKind;

const DATA: u32 = 0x80;

fn open(bytes: Vec<u8>) -> Box<dyn FileSystem> {
    open_filesystem(mem(bytes), FsKind::Ntfs).expect("parse")
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

/// Root, a directory living in the second `$MFT` fragment, resident and fragmented files,
/// Win32 vs DOS names, a named stream.
fn sample() -> NtfsImage {
    let mut img = NtfsImage::new();
    img.put(16, RecordBuilder::new(16, 1).std_info().file_name(fref(5, 5), "hello.txt", 1).resident(DATA, "", b"hello world").build());
    let docs = RecordBuilder::new(17, 2).dir().std_info().file_name(fref(5, 5), "Docs", 1);
    img.put(17, docs.build());
    let big = pattern(3 * CS as usize + 100, 9);
    img.write(30, &big[..2 * CS as usize]);
    img.write(41, &big[2 * CS as usize..]);
    let runs = [(Some(30), 2), (Some(41), 2)];
    let rec = RecordBuilder::new(18, 1)
        .std_info()
        .file_name(fref(17, 2), "BIGFIL~1.BIN", 2)
        .file_name(fref(17, 2), "big file.bin", 1)
        .non_resident(DATA, "", 0, &runs, big.len() as u64)
        .non_resident(DATA, "secret", 0, &[(Some(50), 1)], 10);
    img.write(50, b"0123456789");
    img.put(18, rec.build());
    img
}

#[test]
fn walks_live_files_through_fragmented_mft() {
    let fs = open(sample().finish());
    assert_eq!(fs.kind(), FsKind::Ntfs);
    let (_, root) = find(fs.as_ref(), "");
    assert!(root.is_dir && root.parent.is_none());
    let (hello, e) = find(fs.as_ref(), "hello.txt");
    assert_eq!((e.size, e.state, e.native_id), (11, EntryState::Allocated, 16));
    assert_eq!(e.times.created, Timestamp::from_filetime(FT));
    assert_eq!(read_all(fs.as_ref(), hello), b"hello world");
    assert!(e.damage.is_empty(), "{:?}", e.damage);

    let (docs, d) = find(fs.as_ref(), "Docs");
    assert!(d.is_dir);
    let (big, b) = find(fs.as_ref(), "Docs/big file.bin");
    assert_eq!(b.parent, Some(docs));
    assert_eq!(b.extents.len(), 2);
    assert_eq!(read_all(fs.as_ref(), big), pattern(3 * CS as usize + 100, 9));
    assert_eq!(b.streams.len(), 1);
    assert_eq!((b.streams[0].0.as_str(), b.streams[0].2), ("big file.bin:secret", 10));
    assert!(fs.children(docs).contains(&big));
    assert!(find(fs.as_ref(), "$MFT").1.extents.len() == 2);
}

#[test]
fn free_space_comes_from_bitmap_or_live_files() {
    let fs = open(sample().finish());
    let free = fs.unallocated();
    let used_at = |lcn: u64| free.iter().any(|r| r.contains(lcn * CS));
    assert!(!used_at(0) && !used_at(4) && !used_at(21) && !used_at(30) && !used_at(41));
    assert!(used_at(35) && used_at(200));
    assert!(fs.damage().is_empty(), "{:?}", fs.damage());

    let fs = open(sample().without_bitmap().finish());
    let free = fs.unallocated();
    assert!(free.iter().any(|r| r.contains(200 * CS)));
    assert!(!free.iter().any(|r| r.contains(30 * CS)));
    assert!(fs.damage().iter().any(|d| d.note().contains("$Bitmap")));
}

#[test]
fn deleted_and_orphaned_records() {
    let mut img = sample();
    img.put(19, RecordBuilder::new(19, 4).deleted().std_info().file_name(fref(17, 2), "gone.txt", 1).resident(DATA, "", b"bye").build());
    // Parent record 25 never existed; parent 17 with a stale sequence number was reused.
    img.put(20, RecordBuilder::new(20, 1).std_info().file_name(fref(25, 1), "lost.txt", 1).build());
    img.put(21, RecordBuilder::new(21, 1).deleted().file_name(fref(17, 9), "stale.txt", 1).build());
    // Deleted directory (sequence bumped on free) with a deleted child.
    img.put(22, RecordBuilder::new(22, 3).dir().deleted().file_name(fref(5, 5), "OldDir", 1).build());
    img.put(23, RecordBuilder::new(23, 2).deleted().file_name(fref(22, 2), "inner.txt", 1).build());
    let fs = open(img.finish());
    let (gone, g) = find(fs.as_ref(), "Docs/gone.txt");
    assert_eq!(g.state, EntryState::Deleted);
    assert_eq!(read_all(fs.as_ref(), gone), b"bye");
    assert_eq!(find(fs.as_ref(), "$Orphans/lost.txt").1.state, EntryState::Orphan);
    assert_eq!(find(fs.as_ref(), "$Orphans/stale.txt").1.state, EntryState::Orphan);
    assert_eq!(find(fs.as_ref(), "OldDir/inner.txt").1.state, EntryState::Deleted);
    assert!(find(fs.as_ref(), "$Orphans").1.is_dir);
}

#[test]
fn broken_fixup_keeps_record_with_damage() {
    let mut img = sample();
    let mut rec = RecordBuilder::new(19, 1).std_info().file_name(fref(5, 5), "torn.txt", 1).resident(DATA, "", b"x").build();
    rec[1022] = 0xEE;
    img.put(19, rec);
    let fs = open(img.finish());
    let (_, e) = find(fs.as_ref(), "torn.txt");
    assert!(e.damage.iter().any(|d| d.note().contains("fixup")), "{:?}", e.damage);
}

#[test]
fn attribute_list_extension_records_supply_data_runs() {
    let mut img = sample();
    let content = pattern(5000, 3);
    img.write(60, &content);
    let mut list = Vec::new();
    for (type_code, record) in [(0x10u32, 24u64), (0x30, 24), (DATA, 25)] {
        let mut e = vec![0u8; 0x20];
        e[0..4].copy_from_slice(&type_code.to_le_bytes());
        e[4..6].copy_from_slice(&0x20u16.to_le_bytes());
        e[7] = 0x1A;
        e[0x10..0x18].copy_from_slice(&fref(record, 1).to_le_bytes());
        list.extend_from_slice(&e);
    }
    let base = RecordBuilder::new(24, 1).std_info().resident(0x20, "", &list).file_name(fref(5, 5), "split.dat", 1);
    img.put(24, base.build());
    let ext = RecordBuilder::new(25, 1).base(fref(24, 1)).non_resident(DATA, "", 0, &[(Some(60), 2)], 5000);
    img.put(25, ext.build());
    let fs = open(img.finish());
    let (id, e) = find(fs.as_ref(), "split.dat");
    assert_eq!(e.size, 5000);
    assert_eq!(read_all(fs.as_ref(), id), content);
    assert!(!fs.entries().iter().any(|e| e.native_id == 25), "extension record is not a file");
}

#[test]
fn sparse_runs_and_compressed_files() {
    let mut img = sample();
    img.write(70, &pattern(CS as usize, 1));
    let sparse = RecordBuilder::new(19, 1).std_info().file_name(fref(5, 5), "sparse.bin", 1).non_resident(
        DATA,
        "",
        0,
        &[(None, 2), (Some(70), 1)],
        3 * CS,
    );
    img.put(19, sparse.build());
    // One LZNT1 chunk "abc" + back-reference(len 9, distance 3), in a 16-cluster unit.
    let token: u16 = (2 << 12) | 6;
    let mut body = vec![0b0000_1000, b'a', b'b', b'c'];
    body.extend_from_slice(&token.to_le_bytes());
    let mut unit = (0x8000u16 | 0x3000 | (body.len() as u16 - 1)).to_le_bytes().to_vec();
    unit.extend_from_slice(&body);
    img.write(80, &unit);
    let comp = RecordBuilder::new(20, 1).std_info().file_name(fref(5, 5), "packed.txt", 1).non_resident_flags(
        DATA,
        "",
        0,
        &[(Some(80), 1), (None, 15)],
        12,
        0x0001,
        4,
    );
    img.put(20, comp.build());
    let fs = open(img.finish());
    let (id, e) = find(fs.as_ref(), "sparse.bin");
    let data = read_all(fs.as_ref(), id);
    assert!(data[..2 * CS as usize].iter().all(|b| *b == 0));
    assert_eq!(&data[2 * CS as usize..], &pattern(CS as usize, 1)[..]);
    assert_eq!(e.extents[0].volume_offset, None);
    let (id, _) = find(fs.as_ref(), "packed.txt");
    assert_eq!(read_all(fs.as_ref(), id), b"abcabcabcabc");
}

#[test]
fn carves_stray_records_from_free_space() {
    let mut img = sample();
    let stray = RecordBuilder::new(4321, 3).std_info().file_name(fref(900, 1), "wallet.dat", 1).resident(DATA, "", b"keys").build();
    img.write_free(150 * CS as usize, &stray);
    let bytes = img.finish();
    let plain = open(bytes.clone());
    assert!(!plain.entries().iter().any(|e| e.name == "wallet.dat"));
    let fs = open_filesystem_with(mem(bytes), FsKind::Ntfs, FsOptions::default().with_record_carving(true)).unwrap();
    let (id, e) = find(fs.as_ref(), "$Orphans/wallet.dat");
    assert_eq!((e.state, e.native_id), (EntryState::Orphan, 4321));
    assert_eq!(read_all(fs.as_ref(), id), b"keys");
    assert!(fs.children(e.parent.unwrap()).contains(&id));
}

#[test]
fn falls_back_to_backup_boot_sector_and_mirror() {
    let mut img = sample();
    let boot: Vec<u8> = img.bytes_mut()[..512].to_vec();
    let mirror = img.bytes_mut()[NtfsImage::record_offset(0)..NtfsImage::record_offset(0) + RS].to_vec();
    let len = img.bytes_mut().len();
    img.bytes_mut()[len - 512..].copy_from_slice(&boot);
    img.bytes_mut()[..512].fill(0);
    img.write_free(2 * CS as usize, &mirror);
    let mut bytes = img.finish();
    let rec0 = NtfsImage::record_offset(0);
    bytes[rec0..rec0 + RS].fill(0xAB);
    let fs = open(bytes);
    assert_eq!(find(fs.as_ref(), "hello.txt").1.size, 11);
    let notes: Vec<&str> = fs.damage().iter().map(|d| d.note()).collect();
    assert!(notes.iter().any(|n| n.contains("backup")) && notes.iter().any(|n| n.contains("$MFTMirr")), "{notes:?}");
}

#[test]
fn hostile_input_never_panics() {
    assert!(open_filesystem(mem(vec![0u8; 1 << 20]), FsKind::Ntfs).is_err());
    assert!(open_filesystem(mem(Vec::new()), FsKind::Ntfs).is_err());
    let good = sample().finish();
    for cut in [100, 512, 20_000, 90_000, 200_000] {
        let _ = open_filesystem(mem(good[..cut].to_vec()), FsKind::Ntfs);
    }
    for seed in 1..40u64 {
        let _ = open_filesystem(mem(noise(256 << 10, seed)), FsKind::Ntfs);
        // Valid boot sector and MFT location, garbage records.
        let mut img = good.clone();
        let mft = NtfsImage::record_offset(1);
        let junk = noise(8 * RS, seed);
        img[mft..mft + junk.len()].copy_from_slice(&junk);
        for k in 0..8 {
            img[mft + k * RS..mft + k * RS + 4].copy_from_slice(b"FILE");
        }
        let fs = open_filesystem_with(mem(img), FsKind::Ntfs, FsOptions::default().with_record_carving(true)).unwrap();
        for i in 0..fs.entries().len() {
            let mut buf = [0u8; 64];
            let _ = fs.read(FileId::new(i), 0, &mut buf);
        }
    }
}
