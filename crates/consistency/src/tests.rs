//! Assessments of made-up disks: a quick-formatted data disk, an MFT read only in part, a
//! volume Strata could not list, a normally used system, a reinstall, a cleaned system, little
//! use and a disk not analysed yet.

use super::*;
use strata_kernel::Timestamp;

const GB: u64 = 1 << 30;

fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

fn volume(index: u32, len: u64, live: Tally) -> VolumeInputs {
    VolumeInputs {
        index,
        fs: "NTFS".into(),
        recognised: true,
        len,
        recovered: false,
        live,
        deleted: Tally::default(),
        orphan: Tally::default(),
        folders: live.files / 10,
        file_table: Some(FileTable { bytes: (live.files + live.files / 10 + 16) * 1024, created: Some(at(2009, 1, 5)) }),
        previous_windows: 0,
    }
}

/// Activity made of `(from, to, active days)` periods.
fn activity(periods: &[(Timestamp, Timestamp, u32)]) -> Activity {
    let spans: Vec<ActiveSpan> = periods.iter().map(|&(from, to, active_days)| ActiveSpan { from, to, active_days }).collect();
    Activity {
        first_day: spans.first().map(|s| s.from),
        last_day: spans.last().map(|s| s.to),
        active_days: spans.iter().map(|s| s.active_days).sum(),
        events: spans.iter().map(|s| u64::from(s.active_days) * 40).sum(),
        periods: spans,
    }
}

fn windows(installed: Timestamp, activity: Activity) -> Installation {
    Installation { label: "Microsoft Windows XP".into(), volume: Some(0), installed: Some(installed), previous: false, activity }
}

/// A Windows XP laptop used daily for three years, half full.
fn used_laptop() -> DiskInputs {
    let use_ = activity(&[(at(2009, 2, 1), at(2010, 6, 30), 380), (at(2010, 8, 15), at(2012, 1, 31), 410)]);
    DiskInputs {
        disk_len: 80 * GB,
        indexed: true,
        volumes: vec![volume(0, 80 * GB, Tally::new(60_000, 40 * GB))],
        profiles: vec![ProfileFolder { volume: 0, user: "alice".into(), live: Tally::new(9_000, 3 * GB), deleted: Tally::default() }],
        history: vec![HistoryCount { artifact: "chrome.history".into(), events: 30_000 }],
        hits: HitPlacement { live: 900, deleted: 100, free: 300 },
        installations: vec![windows(at(2009, 1, 5), use_.clone())],
        activity: use_,
        ..Default::default()
    }
}

fn signals(a: &Assessment) -> Vec<Signal> {
    a.observations.iter().map(|o| o.signal).collect()
}

fn find(a: &Assessment, signal: Signal) -> &Observation {
    a.observations.iter().find(|o| o.signal == signal).unwrap_or_else(|| panic!("no {signal:?} in {:?}", signals(a)))
}

#[test]
fn normally_used_system_has_only_context() {
    let a = Assessment::of(&used_laptop());
    assert_eq!(a.verdict.kind, VerdictKind::NormallyUsed, "{:?}", a.observations);
    assert_eq!(a.verdict.headline, "Looks normally used");
    assert!(a.observations.iter().all(|o| o.severity == Severity::Info), "{:?}", signals(&a));
    assert!(!a.needs_attention());
    assert_eq!(find(&a, Signal::LastActivity).title, "Last user activity on 2012-01-31");
}

#[test]
fn quick_formatted_disk_is_flagged_loudly() {
    let mut v = volume(0, 298 * GB, Tally::new(24, 98 << 20));
    v.folders = 17;
    v.file_table = Some(FileTable { bytes: 256 << 10, created: Some(at(2025, 3, 10)) });
    let disk = DiskInputs {
        disk_len: 298 * GB,
        indexed: true,
        volumes: vec![v],
        hits: HitPlacement { live: 0, deleted: 30, free: 27_000 },
        ..Default::default()
    };
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::WipedOrReinstalled);
    assert_eq!(a.verdict.headline, "Probably wiped or reinstalled on 2025-03-10");
    let sparse = &a.observations[0];
    assert_eq!((sparse.signal, sparse.severity, sparse.volume), (Signal::SparseFileTable, Severity::Alert, Some(0)));
    assert_eq!(sparse.title, "File table covers 0.03% of volume 0");
    assert!(sparse.explanation.contains("Either the MFT is damaged, the disk was quick-formatted, or Strata failed to read it"));
    assert!(sparse.explanation.contains("formatted or wiped on 2025-03-10"));
    assert!(signals(&a).contains(&Signal::FindingsOutsideFiles));
    assert!(!signals(&a).contains(&Signal::MissingFileRecords), "a 256-record MFT was read whole");
}

#[test]
fn empty_new_disk_is_little_use_not_wiped() {
    let mut v = volume(0, 500 * GB, Tally::new(3, 1 << 20));
    v.file_table = Some(FileTable { bytes: 256 << 10, created: Some(at(2024, 5, 1)) });
    let disk = DiskInputs { disk_len: 500 * GB, indexed: true, volumes: vec![v], ..Default::default() };
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::LittleUse);
    assert!(find(&a, Signal::SparseFileTable).explanation.contains("left almost unused"));
}

#[test]
fn partly_read_mft_means_strata_failed() {
    let mut v = volume(0, 100 * GB, Tally::new(1_100, 60 * GB));
    v.file_table = Some(FileTable { bytes: 300 << 20, created: Some(at(2011, 4, 2)) });
    let a = Assessment::of(&DiskInputs { disk_len: 100 * GB, indexed: true, volumes: vec![v], ..Default::default() });
    assert_eq!(a.verdict.kind, VerdictKind::Unreadable);
    assert_eq!(a.verdict.headline, "Strata could not read the file system");
    let o = find(&a, Signal::MissingFileRecords);
    assert_eq!(o.title, "Volume 0: Strata read 1,210 of about 307,200 file records");
}

#[test]
fn listed_volume_without_entries_is_unreadable() {
    let mut empty = volume(1, 200 * GB, Tally::default());
    empty.folders = 0;
    empty.fs = "FAT32".into();
    empty.file_table = None;
    let mut disk = used_laptop();
    disk.volumes.push(empty);
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::Unreadable);
    let o = &a.observations[0];
    assert_eq!((o.signal, o.volume), (Signal::UnreadVolume, Some(1)));
    assert!(o.explanation.contains("200 GB of FAT32"));
    // An unrecognised volume next to a readable one is a warning, not the verdict.
    let mut disk = used_laptop();
    disk.volumes.push(VolumeInputs { recognised: false, fs: "Unknown filesystem".into(), file_table: None, ..volume(1, 50 * GB, Tally::default()) });
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::NormallyUsed);
    assert_eq!(find(&a, Signal::UnknownFileSystem).severity, Severity::Warning);
}

#[test]
fn reinstall_over_earlier_use_is_dated() {
    let use_ = activity(&[(at(2009, 3, 1), at(2012, 4, 30), 600), (at(2012, 6, 3), at(2012, 6, 9), 4)]);
    let mut disk = used_laptop();
    disk.installations = vec![windows(at(2012, 6, 1), use_.clone())];
    disk.activity = use_;
    disk.volumes[0].file_table = Some(FileTable { bytes: 70 << 20, created: Some(at(2012, 6, 1)) });
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.headline, "Probably wiped or reinstalled on 2012-06-01");
    let o = find(&a, Signal::InstalledOverActivity);
    assert_eq!(o.severity, Severity::Warning);
    assert_eq!(o.title, "Microsoft Windows XP installed on 2012-06-01, after 600 days of earlier use");
    assert!(o.explanation.contains("Only 4 active days follow the install"));
    // The format that came with the install is the same event, not a second warning.
    assert_eq!(find(&a, Signal::Formatted).severity, Severity::Info);
    // Windows 10 moves its install date on feature updates: only a notice.
    disk.installations[0].label = "Windows 10 Pro".into();
    let a = Assessment::of(&disk);
    assert_eq!(find(&a, Signal::InstalledOverActivity).severity, Severity::Notice);
    assert_eq!(a.verdict.kind, VerdictKind::NormallyUsed);
}

#[test]
fn cleaned_system_shows_tools_gaps_and_missing_history() {
    let mut disk = used_laptop();
    disk.activity = activity(&[(at(2010, 1, 1), at(2012, 8, 31), 500), (at(2019, 5, 1), at(2021, 12, 17), 120)]);
    disk.history.clear();
    disk.programs = vec![
        ProgramRow { title: "CCleaner".into(), trace: ProgramTrace::Installed, first: at(2011, 2, 1), last: at(2011, 2, 1), count: 1 },
        ProgramRow { title: "CCleaner.lnk".into(), trace: ProgramTrace::Ran, first: at(2011, 3, 1), last: at(2012, 7, 1), count: 14 },
        ProgramRow { title: "Mozilla Firefox (3.6.13)".into(), trace: ProgramTrace::Installed, first: at(2010, 2, 1), last: at(2010, 2, 1), count: 1 },
    ];
    disk.named_files = vec![NamedFile { volume: 0, path: "Program Files/Eraser/Eraser.exe".into(), state: EntryState::Deleted }];
    disk.volumes[0].deleted = Tally::new(70_000, 5 * GB);
    let a = Assessment::of(&disk);
    let cc = a.observations.iter().find(|o| o.title == "CCleaner installed and run").expect("CCleaner");
    assert_eq!(cc.severity, Severity::Warning);
    assert!(cc.figures.iter().any(|f| f.label == "Runs recorded" && f.value == "14"));
    let eraser = a.observations.iter().find(|o| o.title == "Eraser found").expect("Eraser file");
    assert!(eraser.figures.iter().any(|f| f.value == "Program Files/Eraser/Eraser.exe (deleted)"));
    assert_eq!(find(&a, Signal::BrowserWithoutHistory).title, "Mozilla Firefox installed but no history");
    assert_eq!(find(&a, Signal::ActivityGap).title, "No activity for 6.7 years (2012-08 to 2019-05)");
    assert_eq!(find(&a, Signal::DeletedMajority).severity, Severity::Warning);
    assert!(a.needs_attention());
    assert_eq!(a.verdict.kind, VerdictKind::NormallyUsed, "cleaning alone does not make a disk wiped");
}

#[test]
fn little_use_and_empty_profiles() {
    let mut disk = used_laptop();
    disk.activity = activity(&[(at(2015, 3, 1), at(2015, 3, 20), 9)]);
    disk.profiles = vec![
        ProfileFolder { volume: 0, user: "bob".into(), live: Tally::new(12, 40 << 10), deleted: Tally::new(300, 1 << 30) },
        ProfileFolder { volume: 0, user: "Default User".into(), live: Tally::new(3, 1024), deleted: Tally::default() },
    ];
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::LittleUse);
    let empty = find(&a, Signal::EmptyProfile);
    assert_eq!(empty.title, "User folder bob almost empty");
    assert!(empty.explanation.contains("300 deleted files remain in them"));
    // A system without any activity at all is a warning.
    disk.activity = Activity::default();
    let a = Assessment::of(&disk);
    assert_eq!(find(&a, Signal::NoActivity).severity, Severity::Warning);
}

#[test]
fn nothing_read_yet_is_not_judged() {
    let disk = DiskInputs { disk_len: 40 * GB, indexed: false, volumes: vec![volume(0, 40 * GB, Tally::default())], ..Default::default() };
    let a = Assessment::of(&disk);
    assert_eq!(a.verdict.kind, VerdictKind::NotAnalysed);
    assert_eq!(a.observations[0].signal, Signal::NotIndexed);
    let blank = DiskInputs { disk_len: 40 * GB, indexed: true, ..Default::default() };
    assert_eq!(Assessment::of(&blank).verdict.kind, VerdictKind::Unreadable, "no partitions and no file system");
}
