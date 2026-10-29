//! The unpack step end to end: an archive carved from free space of a raw image is unpacked
//! recursively and the key inside the innermost member is stored with its virtual path.

use strata_identify::testkit;
use strata_workbench::{HitCategory, HitQuery, JobKind, JobState, Workbench};

const WIF: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

#[test]
fn carved_nested_archive_yields_the_key_with_its_member_path() {
    let note = format!("old wallet\n{WIF}\n");
    let gz = testkit::gzip("keys.txt", note.as_bytes());
    let t = testkit::tar(&[("backup/keys.txt.gz", &gz)]);
    let zip = testkit::zip(&[("bundle.tar", &t, true), ("readme.txt", b"hello", false)]);

    let dir = tempfile::tempdir().unwrap();
    let mut disk = vec![0u8; 2 << 20];
    disk[0x10000..0x10000 + zip.len()].copy_from_slice(&zip);
    let img = dir.path().join("disk.img");
    std::fs::write(&img, &disk).unwrap();

    let wb = Workbench::open(&dir.path().join("t.strata")).unwrap();
    let id = wb.add_evidence(&img.display().to_string()).unwrap().id;
    let carve = wb.run_step(JobKind::Carve, id).unwrap();
    assert!(matches!(carve.state, JobState::Done(_)), "{:?}", carve.state);
    let step = wb.run_step(JobKind::Archives, id).unwrap();
    let JobState::Done(summary) = &step.state else { panic!("{:?}", step.state) };
    assert!(summary.starts_with("1 archives (2 nested)"), "{summary}");

    let hits = wb.hits(&HitQuery { categories: vec![HitCategory::PrivateKey], ..HitQuery::default() }).unwrap();
    let key = hits.iter().find(|h| h.hit.value.contains(WIF) || h.hit.label.contains("WIF")).expect("WIF found");
    assert_eq!(
        key.file_path.as_deref(),
        Some("$Carved/zip@0x10000!/bundle.tar!/backup/keys.txt.gz!/keys.txt")
    );
    assert_eq!(key.hit.offset, 0x10000);
    assert_eq!(key.file_offset, Some(11));
    assert_eq!(key.hit.details["archive_chain"].as_array().map(Vec::len), Some(3));

    let members = wb.case().archive_members(id).unwrap();
    assert_eq!(members.len(), 4);
    // Re-running the step changes nothing.
    wb.run_step(JobKind::Archives, id).unwrap();
    assert_eq!(wb.hits(&HitQuery { categories: vec![HitCategory::PrivateKey], ..HitQuery::default() }).unwrap().len(), hits.len());
}
