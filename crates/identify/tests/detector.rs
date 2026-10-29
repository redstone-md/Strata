//! SignatureDetector over a synthetic "disk" and `measure` on every walkable type.

use strata_identify::testkit as tk;
use strata_identify::{SignatureDetector, TypeId, measure};
use strata_kernel::scan::{Detector, Hit};

fn disk() -> (Vec<u8>, Vec<(usize, TypeId, usize)>) {
    let files: Vec<(Vec<u8>, TypeId)> = vec![
        (tk::zip(&[("a.txt", b"hello", false), ("b.bin", &tk::random(3000, 1), true)]), TypeId::Zip),
        (tk::png(40, 40), TypeId::Png),
        (tk::jpeg(9000), TypeId::Jpeg),
        (tk::pdf(25), TypeId::Pdf),
        (tk::sqlite(&[("t", "CREATE TABLE t(x)")], &[b"row"], 2), TypeId::Sqlite),
        (tk::bdb_wallet(3), TypeId::BitcoinCoreBdb),
        (tk::ole(&["WordDocument"], 4096), TypeId::Doc),
        (tk::pe(true), TypeId::Dll),
        (tk::gzip("x", &tk::lorem(4000)), TypeId::Gzip),
        (tk::rar4(&[("w.dat", &tk::random(500, 3))]), TypeId::Rar4),
        (tk::tar(&[("a", b"b")]), TypeId::Tar),
    ];
    let mut disk = tk::random(4096, 77);
    let mut placed = Vec::new();
    for (bytes, id) in files {
        let at = disk.len();
        disk.extend_from_slice(&bytes);
        placed.push((at, id, bytes.len()));
        let pad = 512 - disk.len() % 512 + 1024;
        disk.extend_from_slice(&tk::random(pad, at as u64));
    }
    (disk, placed)
}

/// Scan like the engine: overlapping chunks, drop hits starting in the overlap tail.
fn scan(det: &SignatureDetector, data: &[u8], chunk: usize) -> Vec<Hit> {
    let overlap = det.max_match();
    let mut hits = Vec::new();
    let mut base = 0;
    while base < data.len() {
        let end = (base + chunk + overlap).min(data.len());
        let mut local: Vec<Hit> = Vec::new();
        det.scan(&data[base..end], base as u64, &mut local);
        let limit = if base + chunk >= data.len() { u64::MAX } else { (base + chunk) as u64 };
        hits.extend(local.into_iter().filter(|h| h.offset < limit));
        base += chunk;
    }
    hits
}

#[test]
fn finds_every_file_start_once() {
    let (disk, placed) = disk();
    let det = SignatureDetector::new();
    let hits = scan(&det, &disk, 64 * 1024 + 512);
    for (at, id, _) in &placed {
        let found: Vec<&Hit> = hits.iter().filter(|h| h.offset == *at as u64).collect();
        assert_eq!(found.len(), 1, "{id} at {at:#x}: {hits:?}");
        assert_eq!(found[0].details["type_id"], id.key(), "{id}");
    }
    assert_eq!(hits.len(), placed.len(), "no spurious hits: {hits:?}");
}

#[test]
fn unaligned_mode_finds_embedded_files() {
    let mut data = tk::random(10_000, 5);
    let png = tk::png(16, 16);
    data.splice(1234..1234, png.iter().copied());
    let det = SignatureDetector::new().with_alignment(1);
    let mut hits: Vec<Hit> = Vec::new();
    det.scan(&data, 0, &mut hits);
    assert!(hits.iter().any(|h| h.offset == 1234 && h.details["type_id"] == "png"), "{hits:?}");
}

#[test]
fn random_data_yields_nothing() {
    let data = tk::random(8 << 20, 9);
    let mut hits: Vec<Hit> = Vec::new();
    SignatureDetector::new().scan(&data, 0, &mut hits);
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn measures_lengths_from_type_structure() {
    let (disk, placed) = disk();
    for (at, id, len) in placed {
        let view = &disk[at..];
        let m = measure(id, &view, 64 << 20).unwrap_or_else(|| panic!("{id} not measured"));
        assert_eq!(m.len, len as u64, "{id}: {m:?}");
    }
}
