//! Evidence consistency read back from a case: a big NTFS volume with a freshly formatted file
//! table and findings in free space, a second volume the index holds nothing for, a cleaning
//! program and a browser without history. Volumes are recorded, not real; all values are made up.

use strata_case::{Attribution, JobStamp};
use strata_fs::{EntryState, FileEntry};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{ByteRange, Confidence, EvidenceId, Timestamp};
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_volume::{FsKind, Volume, VolumeOrigin};
use strata_workbench::{Severity, Signal, VerdictKind, Workbench};

const GIB: u64 = 1 << 30;

fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

fn entry(path: &str, size: u64, is_dir: bool) -> FileEntry {
    let name = path.rsplit('/').next().unwrap_or(path);
    let mut e = FileEntry::new(name, is_dir, EntryState::Allocated, 0);
    e.path = path.into();
    e.size = size;
    e.times.created = Some(at(2025, 3, 10));
    e
}

fn ntfs(start: u64, len: u64) -> Volume {
    Volume { index: 0, range: ByteRange::new(start, len), fs: FsKind::Ntfs, origin: VolumeOrigin::Mbr, label: String::new() }
}

/// A disk with a 298 GiB NTFS volume holding a fresh file table, findings outside files, a
/// CCleaner install and Firefox without history; `unread` adds a 100 GiB volume left unlisted.
fn disk(wb: &Workbench, dir: &std::path::Path, name: &str, unread: bool) -> EvidenceId {
    let image = dir.join(name);
    std::fs::write(&image, vec![0u8; 1 << 16]).unwrap();
    let id = wb.add_evidence(&image.display().to_string()).unwrap().id;
    let mut volumes = vec![ntfs(1 << 20, 298 * GIB)];
    if unread {
        volumes.push(ntfs(299 * GIB, 100 * GIB));
    }
    wb.case().add_volumes(id, &volumes).unwrap();
    let files = [
        entry("$MFT", 256 << 10, false),
        entry("$LogFile", 64 << 20, false),
        entry("System Volume Information", 0, true),
        entry("System Volume Information/tracking.log", 20 << 10, false),
        entry("Program Files/Mozilla Firefox/firefox.exe", 600 << 10, false),
    ];
    let program = |kind, title: &str, t| TimelineEvent::new(t, kind, title, EventSource::new("registry.software", "Windows/System32/config/SOFTWARE"));
    let events = [program(EventKind::ProgramInstalled, "CCleaner", at(2025, 3, 11)), program(EventKind::ProgramRun, "CCleaner.lnk", at(2025, 3, 12))];
    wb.case()
        .write(|w| {
            w.files(id, 0, &files)?;
            w.volume_events(id, 0, &events).map(|_| ())
        })
        .unwrap();
    let hits: Vec<_> = (0..250u64)
        .map(|i| {
            let value = format!("user{i}@example.com");
            (Hit::new("accounts.email", HitCategory::Identity, 4096 * i, value.len()).value(value).confidence(Confidence::new(0.8)), Attribution::default())
        })
        .collect();
    wb.case().store_hits(id, &hits).unwrap();
    let job = wb.case().add_job(1, id, "IndexFiles", "Index files", "Queued").unwrap();
    wb.case().update_job(job, "Done", "", JobStamp::Finished).unwrap();
    id
}

#[test]
fn formatted_and_unread_volumes_are_judged_from_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let wb = Workbench::open_idle(&dir.path().join("c.strata")).unwrap();

    let formatted = disk(&wb, dir.path(), "formatted.img", false);
    let a = wb.consistency(formatted).unwrap();
    assert_eq!(a.verdict.kind, VerdictKind::WipedOrReinstalled, "{:#?}", a.observations);
    assert_eq!(a.verdict.headline, "Probably wiped or reinstalled on 2025-03-10");
    let sparse = &a.observations[0];
    assert_eq!((sparse.signal, sparse.severity, sparse.volume), (Signal::SparseFileTable, Severity::Alert, Some(0)));
    assert!(sparse.title.starts_with("File table covers 0.02% of volume 0"), "{}", sparse.title);
    let signals: Vec<Signal> = a.observations.iter().map(|o| o.signal).collect();
    for s in [Signal::FindingsOutsideFiles, Signal::CleaningTool, Signal::BrowserWithoutHistory, Signal::Formatted] {
        assert!(signals.contains(&s), "{s:?} missing from {signals:?}");
    }
    let cc = a.observations.iter().find(|o| o.signal == Signal::CleaningTool).unwrap();
    assert_eq!(cc.title, "CCleaner installed and run");

    let unread = disk(&wb, dir.path(), "unread.img", true);
    let a = wb.consistency(unread).unwrap();
    assert_eq!(a.verdict.kind, VerdictKind::Unreadable);
    assert_eq!(a.verdict.headline, "Strata could not read the file system");
    let o = a.observations.iter().find(|o| o.signal == Signal::UnreadVolume).expect("the unlisted volume");
    assert_eq!((o.severity, o.volume), (Severity::Alert, Some(1)));
}
