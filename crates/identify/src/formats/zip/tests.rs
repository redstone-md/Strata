use super::*;
use crate::testkit;

fn sample() -> (Vec<u8>, Vec<u8>) {
    let big = testkit::lorem(20_000);
    let zip = testkit::zip(&[
        ("readme.txt", b"hello zip", false),
        ("data/big.txt", &big, true),
        ("wallet.dat", &testkit::random(3000, 1), true),
    ]);
    (zip, big)
}

#[test]
fn reads_central_directory_and_extracts() {
    let (zip, big) = sample();
    let a = ZipArchive::parse(&zip);
    assert_eq!(a.source(), EntrySource::CentralDirectory);
    assert_eq!(a.entries().len(), 3);
    assert_eq!(a.declared_len(), Some(zip.len() as u64));
    let e = a.find("data/big.txt").unwrap();
    let ex = a.extract(&zip, e, usize::MAX);
    assert!(ex.is_intact());
    assert_eq!(ex.data, big);
    let e = a.find("readme.txt").unwrap();
    assert_eq!(a.extract(&zip, e, 100).data, b"hello zip");
}

#[test]
fn rebuilds_from_local_headers_when_central_directory_lost() {
    let (zip, _) = sample();
    let cd = memmem::find(&zip, CENTRAL_SIG).unwrap();
    let cut = &zip[..cd];
    let a = ZipArchive::parse(cut);
    assert_eq!(a.source(), EntrySource::LocalHeaders);
    assert_eq!(a.entries().len(), 3);
    for e in a.entries() {
        assert!(a.extract(cut, e, usize::MAX).is_intact(), "{}", e.name);
    }
}

#[test]
fn damaged_member_reported_others_extracted() {
    let (mut zip, _) = sample();
    let a = ZipArchive::parse(&zip);
    let start = a.find("data/big.txt").unwrap().data_start.unwrap();
    zip[start + 50..start + 120].fill(0);
    let a = ZipArchive::parse(&zip);
    let bad = a.extract(&zip, a.find("data/big.txt").unwrap(), usize::MAX);
    assert!(!bad.is_intact());
    assert!(!bad.damage.is_empty());
    assert!(a.extract(&zip, a.find("readme.txt").unwrap(), 100).is_intact());
    assert!(a.extract(&zip, a.find("wallet.dat").unwrap(), usize::MAX).is_intact());
}

#[test]
fn headerless_fragment_still_lists_members() {
    let (zip, _) = sample();
    let frag = &zip[40..];
    let a = ZipArchive::parse(frag);
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"data/big.txt") && names.contains(&"wallet.dat"));
    assert!(a.extract(frag, a.find("wallet.dat").unwrap(), usize::MAX).is_intact());
}

#[test]
fn end_of_archive_found_in_view() {
    let (mut zip, _) = sample();
    let len = zip.len() as u64;
    zip.extend_from_slice(&testkit::random(5000, 3));
    assert_eq!(end_of_archive(&zip.as_slice(), zip.len() as u64), Some(len));
}

#[test]
fn refines_ooxml_and_odf() {
    let docx = testkit::zip(&[("[Content_Types].xml", b"<Types/>", true), ("word/document.xml", b"<w/>", true)]);
    assert_eq!(validate(&docx).unwrap().id(), crate::TypeId::Docx);
    let odt = testkit::zip(&[("mimetype", b"application/vnd.oasis.opendocument.text", false), ("content.xml", b"<x/>", true)]);
    assert_eq!(validate(&odt).unwrap().id(), crate::TypeId::Odt);
    let jar = testkit::zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0", true), ("a/B.class", b"\xCA\xFE\xBA\xBE", false)]);
    assert_eq!(validate(&jar).unwrap().id(), crate::TypeId::Jar);
}

#[test]
fn garbage_never_panics() {
    for seed in 0..200 {
        let mut g = testkit::random(2048, seed);
        for (i, sig) in [LOCAL_SIG, CENTRAL_SIG, EOCD_SIG, records::ZIP64_LOCATOR_SIG].iter().enumerate() {
            let at = (seed as usize * 37 + i * 400) % 2000;
            g[at..at + 4].copy_from_slice(sig);
        }
        let a = ZipArchive::parse(&g);
        for e in a.entries() {
            let _ = a.extract(&g, e, 1 << 20);
        }
        let _ = validate(&g);
    }
}
