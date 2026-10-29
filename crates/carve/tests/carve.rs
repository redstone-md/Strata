//! Carving from an in-memory "disk" with known file placements and bad sectors.

use std::sync::Arc;
use strata_carve::{Boundary, Carver, LengthSource, carve_ranges};
use strata_identify::testkit as tk;
use strata_identify::{SignatureDetector, TypeId};
use strata_kernel::scan::{Detector, Hit, HitCategory};
use strata_kernel::{ByteRange, DamageKind, Result};
use strata_source::{BlockSource, SourceInfo, SourceKind};

struct MemSource {
    data: Vec<u8>,
    bad: Vec<ByteRange>,
}

impl MemSource {
    fn shared(mut data: Vec<u8>, bad: Vec<ByteRange>) -> Arc<dyn BlockSource> {
        for r in &bad {
            data[r.start() as usize..r.end() as usize].fill(0);
        }
        Arc::new(Self { data, bad })
    }
}

impl BlockSource for MemSource {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            kind: SourceKind::RawImage,
            label: "mem".into(),
            location: "memory".into(),
            len: self.len(),
            sector_size: 512,
        }
    }

    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let src = self.data.get(offset as usize..).unwrap_or_default();
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }

    fn damage(&self) -> Vec<ByteRange> {
        self.bad.clone()
    }
}

struct Placed {
    at: u64,
    len: u64,
    id: TypeId,
}

fn disk(files: Vec<(Vec<u8>, TypeId)>, gap: usize) -> (Vec<u8>, Vec<Placed>) {
    let mut disk = tk::random(8192, 1);
    let mut placed = Vec::new();
    for (bytes, id) in files {
        placed.push(Placed { at: disk.len() as u64, len: bytes.len() as u64, id });
        disk.extend_from_slice(&bytes);
        let pad = (512 - disk.len() % 512) % 512 + gap;
        disk.extend_from_slice(&tk::random(pad, disk.len() as u64));
    }
    (disk, placed)
}

fn sized_files() -> Vec<(Vec<u8>, TypeId)> {
    vec![
        (tk::zip(&[("a.txt", b"hello", false), ("keys/wallet.dat", &tk::random(5000, 2), true)]), TypeId::Zip),
        (tk::png(50, 30), TypeId::Png),
        (tk::jpeg(12_000), TypeId::Jpeg),
        (tk::pdf(40), TypeId::Pdf),
        (tk::sqlite(&[("t", "CREATE TABLE t(x)")], &[b"r1", b"r2"], 3), TypeId::Sqlite),
        (tk::bdb_wallet(4), TypeId::BerkeleyDb),
        (tk::ole(&["WordDocument", "1Table"], 4096), TypeId::Ole2),
        (tk::pe(false), TypeId::Pe),
        (tk::gzip("notes.txt", &tk::lorem(9000)), TypeId::Gzip),
        (tk::rar4(&[("w.dat", &tk::random(700, 3))]), TypeId::Rar4),
        (tk::tar(&[("a", b"bc"), ("d", &tk::random(900, 4))]), TypeId::Tar),
    ]
}

#[test]
fn carves_exact_lengths_from_type_structure() {
    let (data, placed) = disk(sized_files(), 4096);
    let carver = Carver::new(MemSource::shared(data, Vec::new()));
    for p in placed {
        let f = carver.carve(p.at, p.id).unwrap();
        assert_eq!(f.range, ByteRange::new(p.at, p.len), "{}: {:?}", p.id, f.length);
        assert!(f.length.is_exact(), "{}", p.id);
        assert!(f.verdict.file_type.spec().same_family(p.id), "{} -> {}", p.id, f.verdict.file_type);
        assert!(f.damage.is_empty(), "{}: {:?}", p.id, f.damage);
    }
}

#[test]
fn falls_back_to_next_header_and_zero_runs() {
    // KeePass has no size information: it ends where the next file's header starts.
    let mut kdbx = b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5\x01\x00\x04\x00".to_vec();
    kdbx.extend_from_slice(&tk::random(10_000, 8));
    let (data, placed) = disk(vec![(kdbx, TypeId::KeePass2), (tk::png(10, 10), TypeId::Png)], 0);
    let carver = Carver::new(MemSource::shared(data, Vec::new()));
    let f = carver.carve(placed[0].at, TypeId::KeePass2).unwrap();
    assert_eq!(f.length, LengthSource::Boundary(Boundary::NextHeader));
    assert_eq!(f.range.end(), placed[1].at);
    assert_eq!(f.verdict.file_type, TypeId::KeePass2);

    // BZIP2 followed by a long zero run.
    let mut bz = b"BZh91AY&SY".to_vec();
    bz.extend_from_slice(&tk::random(20_000, 9));
    let len = bz.len() as u64;
    bz.extend_from_slice(&vec![0u8; 200_000]);
    let carver = Carver::new(MemSource::shared(bz, Vec::new()));
    let f = carver.carve(0, TypeId::Bzip2).unwrap();
    assert_eq!(f.length, LengthSource::Boundary(Boundary::ZeroRun));
    assert_eq!(f.range.len(), len);
}

#[test]
fn reports_source_damage_and_still_identifies() {
    let files = vec![(tk::zip(&[("a.bin", &tk::random(30_000, 5), false), ("b.txt", b"tail member", false)]), TypeId::Zip)];
    let (data, placed) = disk(files, 1024);
    let bad = ByteRange::new(placed[0].at + 8192, 4096);
    let carver = Carver::new(MemSource::shared(data, vec![bad]));
    let f = carver.carve(placed[0].at, TypeId::Zip).unwrap();
    assert_eq!(f.range.len(), placed[0].len);
    assert!(f.damage.iter().any(|d| d.kind() == DamageKind::Unreadable && d.range() == Some(bad)));
    assert_eq!(f.verdict.file_type, TypeId::Zip);
    assert!(f.verdict.valid_fraction < 1.0);
    assert!(f.verdict.inner.iter().any(|i| i.name == "b.txt"));
}

#[test]
fn carve_ranges_uses_detector_hits_and_skips_nested() {
    let (data, placed) = disk(sized_files(), 2048);
    let det = SignatureDetector::new();
    let mut hits: Vec<Hit> = Vec::new();
    det.scan(&data, 0, &mut hits);
    // A fake hit inside the first file must be ignored (nested content).
    hits.push(Hit::new("test", HitCategory::FileSignature, placed[0].at + 512, 4).details(serde_json::json!({"type_id": "jpeg"})));
    // Unallocated space: everything except the 3rd file.
    let third = &placed[2];
    let ranges = vec![ByteRange::from_bounds(0, third.at), ByteRange::from_bounds(third.at + third.len, data.len() as u64)];
    let carved = carve_ranges(MemSource::shared(data, Vec::new()), &ranges, &hits);
    assert_eq!(carved.len(), placed.len() - 1);
    for p in placed.iter().filter(|p| p.at != third.at) {
        let f = carved.iter().find(|f| f.range.start() == p.at).unwrap_or_else(|| panic!("{} not carved", p.id));
        assert_eq!(f.range.len(), p.len, "{}", p.id);
    }
}

#[test]
fn range_end_bounds_the_carve() {
    let zip = tk::zip(&[("big.bin", &tk::random(50_000, 6), false)]);
    let (data, placed) = disk(vec![(zip, TypeId::Zip)], 0);
    let carver = Carver::new(MemSource::shared(data, Vec::new()));
    let end = placed[0].at + 20_000;
    let f = carver.carve_within(placed[0].at, TypeId::Zip, end).unwrap();
    assert!(f.range.end() <= end);
    assert!(carver.carve(u64::MAX - 1, TypeId::Zip).is_err());
}
