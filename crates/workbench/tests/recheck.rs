//! Findings stored by older detector rules are re-checked against the current ones: a hash
//! that was once reported as a key disappears, a real key keeps its place.

use strata_case::Attribution;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::Confidence;
use strata_workbench::{HitQuery, JobKind, JobState, Workbench};

const HASH: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
const KEY: &str = "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd";

#[test]
fn recheck_removes_findings_the_current_rules_reject() {
    let dir = tempfile::tempdir().unwrap();
    let mut disk = vec![0u8; 1 << 20];
    let apt = format!("Package: electrum\nDescription: Bitcoin wallet\nSHA256: {HASH}\n");
    let note = format!("my bitcoin private key\n{KEY}\n");
    disk[0x1000..0x1000 + apt.len()].copy_from_slice(apt.as_bytes());
    disk[0x8000..0x8000 + note.len()].copy_from_slice(note.as_bytes());
    let img = dir.path().join("disk.img");
    std::fs::write(&img, &disk).unwrap();

    let wb = Workbench::open(&dir.path().join("c.strata")).unwrap();
    let id = wb.add_evidence(&img.display().to_string()).unwrap().id;
    // What an older version stored: both runs reported as keys.
    let stored = |offset: u64, value: &str| {
        let hit = Hit::new("crypto.hex_key", HitCategory::PrivateKey, offset, 64).confidence(Confidence::new(0.6)).value(value);
        (hit, Attribution::default())
    };
    let hash_at = 0x1000 + apt.find(HASH).unwrap() as u64;
    let key_at = 0x8000 + note.find(KEY).unwrap() as u64;
    wb.case().store_hits(id, &[stored(hash_at, HASH), stored(key_at, KEY)]).unwrap();

    let job = wb.run_step(JobKind::Recheck, id).unwrap();
    assert!(matches!(job.state, JobState::Done(_)), "{:?}", job.state);
    let left: Vec<String> = wb.hits(&HitQuery::default()).unwrap().into_iter().map(|h| h.hit.value).collect();
    assert_eq!(left, vec![KEY.to_string()]);
}
