//! End-to-end tests over a synthetic two-segment E01 written byte by byte.

use super::section::adler32;
use super::*;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;

const BPS: u32 = 512;
const SPC: u32 = 2;
const CHUNK: usize = (BPS * SPC) as usize;
const SECTORS: u64 = 7;
const MEDIA: usize = SECTORS as usize * BPS as usize;

fn media() -> Vec<u8> {
    (0..MEDIA).map(|i| (i * 7 + i / 13) as u8).collect()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn with_adler(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.extend(adler32(data).to_le_bytes());
    v
}

struct Segment(Vec<u8>);

impl Segment {
    fn new(number: u16) -> Self {
        let mut head = b"EVF\x09\x0d\x0a\xff\x00\x01".to_vec();
        head.extend(number.to_le_bytes());
        head.extend([0, 0]);
        Self(head)
    }

    fn descriptor(kind: &str, next: u64, size: u64) -> Vec<u8> {
        let mut d = [0u8; 76];
        d[..kind.len()].copy_from_slice(kind.as_bytes());
        d[16..24].copy_from_slice(&next.to_le_bytes());
        d[24..32].copy_from_slice(&size.to_le_bytes());
        let sum = adler32(&d[..72]);
        d[72..].copy_from_slice(&sum.to_le_bytes());
        d.to_vec()
    }

    /// Append a section; returns the absolute offset of its payload.
    fn section(&mut self, kind: &str, data: &[u8]) -> usize {
        let start = self.0.len() as u64;
        let size = 76 + data.len() as u64;
        self.0.extend(Self::descriptor(kind, start + size, size));
        self.0.extend(data);
        start as usize + 76
    }

    fn finish(mut self, kind: &str) -> Vec<u8> {
        let start = self.0.len() as u64;
        self.0.extend(Self::descriptor(kind, start, 0));
        self.0
    }

    /// `sectors` with the given stored chunks, then `table` + `table2` (base = payload start).
    /// Returns (offset of each stored chunk, offset of the first `table` entry).
    fn chunks(&mut self, stored: &[(Vec<u8>, bool)]) -> (Vec<usize>, usize) {
        let data: Vec<u8> = stored.iter().flat_map(|(d, _)| d.clone()).collect();
        let base = self.section("sectors", &data);
        let mut rel = 0u32;
        let mut entries = Vec::new();
        let mut at = Vec::new();
        for (d, compressed) in stored {
            entries.push(rel | if *compressed { 0x8000_0000 } else { 0 });
            at.push(base + rel as usize);
            rel += d.len() as u32;
        }
        let mut table = (entries.len() as u32).to_le_bytes().to_vec();
        table.extend([0; 4]);
        table.extend((base as u64).to_le_bytes());
        table.extend([0; 4]);
        table.extend(adler32(&table).to_le_bytes());
        let body: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
        table.extend(&body);
        table.extend(adler32(&body).to_le_bytes());
        let first_entry = self.section("table", &table) + 24;
        self.section("table2", &table);
        (at, first_entry)
    }
}

struct Built {
    segments: [Vec<u8>; 2],
    /// (segment, offset) of each stored chunk.
    chunks: Vec<(usize, usize)>,
    first_table_entry: usize,
}

fn build() -> Built {
    let m = media();
    let mut s1 = Segment::new(1);
    let header = "1\nmain\nc\tn\ta\te\tm\nCASE-42\tEV1\tlost wallet laptop\tAndy\t1700000000\n\n";
    let mut text = vec![0xFF, 0xFE];
    text.extend(header.encode_utf16().flat_map(u16::to_le_bytes));
    s1.section("header2", &zlib(&text));
    let mut volume = vec![0u8; 1052];
    volume[0] = 1;
    volume[4..8].copy_from_slice(&4u32.to_le_bytes());
    volume[8..12].copy_from_slice(&SPC.to_le_bytes());
    volume[12..16].copy_from_slice(&BPS.to_le_bytes());
    volume[16..24].copy_from_slice(&SECTORS.to_le_bytes());
    s1.section("volume", &volume);
    let (at1, first_table_entry) =
        s1.chunks(&[(zlib(&m[..CHUNK]), true), (with_adler(&m[CHUNK..2 * CHUNK]), false)]);

    let mut s2 = Segment::new(2);
    let (at2, _) = s2.chunks(&[(zlib(&m[2 * CHUNK..3 * CHUNK]), true), (with_adler(&m[3 * CHUNK..]), false)]);
    let mut error2 = 1u32.to_le_bytes().to_vec();
    error2.resize(516, 0);
    error2.extend(adler32(&error2.clone()).to_le_bytes());
    error2.extend([6u32.to_le_bytes(), 1u32.to_le_bytes()].concat());
    s2.section("error2", &error2);
    let mut digest = vec![0x11; 16];
    digest.extend([0x22; 20]);
    digest.resize(80, 0);
    s2.section("digest", &digest);

    let chunks = at1.iter().map(|o| (0, *o)).chain(at2.iter().map(|o| (1, *o))).collect();
    Built { segments: [s1.finish("next"), s2.finish("done")], chunks, first_table_entry }
}

fn write(dir: &Path, segments: &[Vec<u8>]) -> PathBuf {
    for (i, s) in segments.iter().enumerate() {
        std::fs::write(dir.join(format!("disk.E{:02}", i + 1)), s).unwrap();
    }
    dir.join("disk.E01")
}

fn read_all(img: &EwfImage) -> Vec<u8> {
    img.read_vec(0, img.len() as usize).unwrap()
}

#[test]
fn reads_split_image_with_metadata_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let img = EwfImage::open(&write(dir.path(), &build().segments)).unwrap();
    assert_eq!((img.len(), img.segment_count(), img.chunk_count(), img.chunk_size()), (MEDIA as u64, 2, 4, 1024));
    assert_eq!(read_all(&img), media());
    assert_eq!(img.read_vec(1000, 100).unwrap(), media()[1000..1100]);
    assert_eq!(img.read_vec(2040, 100).unwrap(), media()[2040..2140]);
    assert_eq!(img.metadata()["case_number"], "CASE-42");
    assert_eq!(img.metadata()["examiner"], "Andy");
    assert_eq!(img.metadata()["acquired"], "2023-11-14 22:13:20");
    assert_eq!(img.stored_hashes().md5(), Some([0x11; 16]));
    assert_eq!(img.stored_hashes().sha1(), Some([0x22; 20]));
    assert_eq!(img.damage(), vec![ByteRange::new(3072, 512)], "error2 sector 6");
    let info = img.info();
    assert_eq!((info.kind, info.sector_size, info.label.as_str()), (SourceKind::EwfImage, 512, "disk (case CASE-42)"));
    assert_eq!(img.table_fallbacks(), 0);
}

#[test]
fn corrupt_chunks_read_as_zeros_and_damage() {
    let built = build();
    let mut segments = built.segments.clone();
    for chunk in [1, 2] {
        let (seg, at) = built.chunks[chunk];
        segments[seg][at + 10] ^= 0x5A;
    }
    let dir = tempfile::tempdir().unwrap();
    let img = EwfImage::open(&write(dir.path(), &segments)).unwrap();
    let data = read_all(&img);
    assert_eq!(data[..CHUNK], media()[..CHUNK]);
    assert!(data[CHUNK..3 * CHUNK].iter().all(|b| *b == 0));
    assert_eq!(data[3 * CHUNK..], media()[3 * CHUNK..]);
    // Chunks 1-2 failed; the error2 sector right after them coalesces into one range.
    assert_eq!(img.damage(), vec![ByteRange::new(1024, 2560)]);
}

#[test]
fn bad_table_checksum_falls_back_to_table2() {
    let built = build();
    let mut segments = built.segments.clone();
    segments[0][built.first_table_entry] ^= 0x40;
    let dir = tempfile::tempdir().unwrap();
    let img = EwfImage::open(&write(dir.path(), &segments)).unwrap();
    assert_eq!(img.table_fallbacks(), 1);
    assert_eq!(read_all(&img), media());
}

#[test]
fn missing_segment_is_damage_not_error() {
    let built = build();
    let dir = tempfile::tempdir().unwrap();
    let img = EwfImage::open(&write(dir.path(), &built.segments[..1])).unwrap();
    assert_eq!(img.len(), MEDIA as u64);
    assert_eq!(read_all(&img)[..2 * CHUNK], media()[..2 * CHUNK]);
    assert_eq!(img.damage(), vec![ByteRange::new(2048, 1536)]);
}

#[test]
fn truncated_or_garbled_segments_never_panic() {
    let built = build();
    let dir = tempfile::tempdir().unwrap();
    let exercise = |segments: &[Vec<u8>]| {
        if let Ok(img) = EwfImage::open(&write(dir.path(), segments)) {
            let _ = img.read_vec(0, img.len().min(1 << 20) as usize);
            let _ = img.damage();
            let _ = img.info();
        }
    };
    for cut in (0..built.segments[0].len()).step_by(9) {
        exercise(&[built.segments[0][..cut].to_vec(), built.segments[1].clone()]);
    }
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..150 {
        let mut segments = built.segments.clone();
        for _ in 0..8 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let seg = &mut segments[(seed & 1) as usize];
            let at = 13 + (seed >> 8) as usize % (seg.len() - 13);
            seg[at] = (seed >> 40) as u8;
        }
        exercise(&segments);
    }
    let mut garbage = b"EVF\x09\x0d\x0a\xff\x00".to_vec();
    garbage.extend((0..4096u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    exercise(&[garbage]);
}
