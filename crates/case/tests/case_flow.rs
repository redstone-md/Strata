use strata_case::{Case, CorrelationService, HitQuery};
use strata_engine::{ScanControl, Scanner};
use strata_kernel::scan::HitCategory;

fn image(dir: &std::path::Path, name: &str, payload: &[u8], at: usize) -> String {
    let mut data = vec![0u8; 1 << 20];
    data[at..at + payload.len()].copy_from_slice(payload);
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    path.display().to_string()
}

#[test]
fn two_disks_share_an_identity() {
    let dir = tempfile::tempdir().unwrap();
    let case = Case::open(&dir.path().join("demo.strata")).unwrap();
    let a = case.add_evidence(&image(dir.path(), "a.img", b"mail: olga.test1@mail.ru ", 5000)).unwrap();
    let b = case.add_evidence(&image(dir.path(), "b.img", b"to olga.test1@mail.ru and bitcointalk.org", 900_000)).unwrap();
    assert_ne!(a.id, b.id);
    let scanner = Scanner::new(strata_accounts::detectors()).with_chunk_size(64 << 10);
    for id in [a.id, b.id] {
        let summary = case.scan(id, &scanner, &ScanControl::default()).unwrap();
        assert!(summary.completed);
    }
    let hits = case.hits(&HitQuery { categories: vec![HitCategory::Identity], ..Default::default() }).unwrap();
    assert_eq!(hits.len(), 2);
    let grouped = case.hits(&HitQuery { categories: vec![HitCategory::Identity], group_by_value: true, ..Default::default() }).unwrap();
    assert_eq!(grouped.len(), 1);
    assert_eq!((grouped[0].occurrences, grouped[0].disks.len()), (2, 2));
    let places = case.hits(&HitQuery { exact_value: Some("olga.test1@mail.ru".into()), ..Default::default() }).unwrap();
    assert_eq!(places.len(), 2);
    let shared = CorrelationService::new(&case).shared_findings(&[HitCategory::Identity]).unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].value, "olga.test1@mail.ru");
    assert_eq!(shared[0].evidence.len(), 2);
    // Re-adding is idempotent; re-scan of a completed scan starts over without duplicates.
    assert_eq!(case.add_evidence(&a.info.location).unwrap().id, a.id);
    case.scan(a.id, &scanner, &ScanControl::default()).unwrap();
    assert_eq!(case.hits(&HitQuery::default()).unwrap().len(), 2);
}
