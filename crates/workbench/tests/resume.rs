//! Crash and resume: the analyse pipeline is "killed" inside each step (a commit that never
//! reaches the case, and no state write after it), the case is reopened, and the resumed run
//! must end with exactly the results of an uninterrupted run — nothing duplicated, nothing
//! lost.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_identify::testkit;
use strata_workbench::{CheckpointPolicy, EventQuery, EvidenceId, HitQuery, JobKind, JobState, Workbench};
use support::{Fat16, disk};

const WIF: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
/// Nothing listens here: balance lookups fail at once instead of reaching the network.
const NO_CHAIN: &str = "http://127.0.0.1:9";

fn image(dir: &Path) -> PathBuf {
    let note = format!("old backup\n{WIF}\n");
    let bundle = testkit::zip(&[("keys.txt", note.as_bytes(), true), ("readme.txt", b"hello", false)]);
    let gz = testkit::gzip("seed.txt", note.as_bytes());
    let nested = testkit::zip(&[("inner.txt.gz", &gz, false)]);
    let a = Fat16::new(2048)
        .file(b"NOTES   TXT", note.as_bytes())
        .file(b"BUNDLE  ZIP", &bundle)
        .file(b"PHOTO   JPG", &nested)
        .file(b"MAIL    TXT", b"write to alice.sample@example.org about the wallet");
    let b = Fat16::new(6 * 2048)
        .file(b"README  TXT", b"nothing here")
        .file(b"ARCHIVE ZIP", &nested)
        .file(b"KEYS    TXT", format!("{WIF} spare").as_bytes());
    let carved = testkit::zip(&[("lost.txt", note.as_bytes(), true)]);
    let bytes = disk(20 << 20, vec![(1, a), (6, b)], &[(12 << 20, &carved), (18 << 20, note.as_bytes())]);
    let path = dir.join("disk.img");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn wait_idle(wb: &Workbench) {
    let until = Instant::now() + Duration::from_secs(300);
    while wb.has_active_jobs() {
        assert!(Instant::now() < until, "pipeline did not finish: {:?}", wb.jobs());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Everything the pipeline stores, in a comparable order.
fn fingerprint(wb: &Workbench, id: EvidenceId) -> Vec<String> {
    let mut out = Vec::new();
    for h in wb.hits(&HitQuery::default()).unwrap() {
        out.push(format!("hit {} {:?} {} {} {:?} {:?}", h.hit.detector, h.hit.category, h.hit.offset, h.hit.value, h.file_path, h.file_offset));
    }
    for (e, ev) in wb.events(&EventQuery::default()).unwrap() {
        out.push(format!("event {e} {} {} {}", ev.at(), ev.title(), ev.source().path));
    }
    for f in wb.host_facts(None).unwrap() {
        out.push(format!("fact {} {} {}", f.key, f.value, f.source));
    }
    for m in wb.case().archive_members(id).unwrap() {
        out.push(format!("member {} {} {:?}", m.member_path, m.recovered, m.detected_type));
    }
    let types: Vec<&str> = strata_identify::Registry::all().iter().map(|t| t.name).collect();
    for (v, i, t) in wb.case().files_of_types(id, &types).unwrap().unwrap_or_default() {
        out.push(format!("file {v} {i} {t}"));
    }
    out.sort();
    out
}

fn open(case: &Path, img: &Path) -> (Arc<Workbench>, EvidenceId) {
    let wb = Workbench::open(case).unwrap();
    wb.set_chain_endpoint(NO_CHAIN).unwrap();
    let id = wb.add_evidence(&img.display().to_string()).unwrap().id;
    (wb, id)
}

fn tiny_batches() -> CheckpointPolicy {
    CheckpointPolicy { every: Duration::ZERO, every_items: 1 }
}

#[test]
fn every_step_resumes_after_a_crash_with_identical_results() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());

    let (clean, id) = open(&dir.path().join("clean.strata"), &img);
    clean.set_checkpoint_policy(tiny_batches());
    clean.analyse(id).unwrap();
    wait_idle(&clean);
    for j in clean.jobs() {
        assert!(matches!(j.state, JobState::Done(_)), "{}: {:?}", j.title, j.state);
    }
    let expected = fingerprint(&clean, id);
    assert!(expected.iter().any(|l| l.starts_with("event")), "the volumes produce timeline events");
    assert!(expected.iter().any(|l| l.starts_with("member")), "archives are unpacked");
    assert!(expected.iter().any(|l| l.contains("carve.unallocated")), "free space is carved");
    assert!(expected.iter().any(|l| l.contains("identify.mismatch")), "the renamed archive is flagged");
    assert!(expected.iter().any(|l| l.starts_with("file")), "file types are stored");
    assert!(expected.iter().any(|l| l.contains("wallet") || l.contains(WIF)), "the key is found");
    drop(clean);

    for kind in [JobKind::IndexFiles, JobKind::Scan, JobKind::Artifacts, JobKind::ClassifyFiles, JobKind::Carve, JobKind::Archives] {
        let case = dir.path().join(format!("{kind:?}.strata"));
        {
            let (wb, id) = open(&case, &img);
            wb.set_checkpoint_policy(tiny_batches());
            wb.crash_after_commits(kind, 1);
            wb.analyse(id).unwrap();
            wait_idle(&wb);
            let crashed = wb.jobs().into_iter().find(|j| j.kind == kind).unwrap();
            assert_eq!(crashed.state, JobState::Interrupted, "{kind:?}");
            assert!(crashed.checkpoint.is_some(), "{kind:?} saved a checkpoint before the crash");
        }
        let wb = Workbench::open(&case).unwrap();
        wait_idle(&wb);
        let jobs = wb.jobs();
        assert_eq!(jobs.len(), JobKind::PIPELINE.len(), "{kind:?}: same jobs, same ids after reopening");
        for j in &jobs {
            assert!(matches!(j.state, JobState::Done(_)), "{kind:?} / {}: {:?}", j.title, j.state);
        }
        assert_eq!(fingerprint(&wb, id), expected, "{kind:?}: resumed results differ from an uninterrupted run");
    }
}

#[test]
fn shutdown_interrupts_and_auto_resume_is_a_case_setting() {
    let dir = tempfile::tempdir().unwrap();
    let img = image(dir.path());
    let case = dir.path().join("s.strata");
    let id = {
        let (wb, id) = open(&case, &img);
        wb.set_auto_resume(false).unwrap();
        wb.analyse(id).unwrap();
        let scan = wb.jobs().into_iter().find(|j| j.kind == JobKind::Scan).unwrap().id;
        wb.pause_job(scan);
        wb.shutdown(Duration::from_secs(60));
        id
    };
    let wb = Workbench::open(&case).unwrap();
    assert!(!wb.has_active_jobs(), "auto-resume is off");
    let states: Vec<_> = wb.jobs().into_iter().map(|j| j.state).collect();
    assert!(states.contains(&JobState::Interrupted), "{states:?}");
    assert_eq!(wb.resume_interrupted(), states.iter().filter(|s| **s == JobState::Interrupted).count());
    wait_idle(&wb);
    assert!(wb.jobs().iter().all(|j| matches!(j.state, JobState::Done(_))), "{:?}", wb.jobs());
    assert!(!wb.hits(&HitQuery { evidence: Some(id), ..HitQuery::default() }).unwrap().is_empty());
}
