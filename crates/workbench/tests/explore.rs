//! Deleted partitions, disk search and recovery end to end on synthetic disk images.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use strata_fs::testkit::{FatVolume, NtfsVolume};
use strata_workbench::{
    Encoding, EvidenceId, FileFilter, FileListQuery, JobKind, JobState, Pattern, Scope, SearchQuery, SearchResultRow, Workbench,
};

const MIB: usize = 1 << 20;

/// A disk of `len` bytes with an MBR holding `entries` (type, start, len in bytes) and the
/// given volumes copied in.
fn disk(len: usize, entries: &[(u8, usize, usize)], volumes: &[(usize, &[u8])]) -> Vec<u8> {
    let mut d = vec![0u8; len];
    for (i, (ty, start, size)) in entries.iter().enumerate() {
        let e = 446 + i * 16;
        d[e + 4] = *ty;
        d[e + 8..e + 12].copy_from_slice(&((start / 512) as u32).to_le_bytes());
        d[e + 12..e + 16].copy_from_slice(&((size / 512) as u32).to_le_bytes());
    }
    d[510] = 0x55;
    d[511] = 0xAA;
    for (at, bytes) in volumes {
        d[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    d
}

fn case_with(dir: &Path, image: &[u8]) -> (Arc<Workbench>, EvidenceId) {
    let path = dir.join("disk.img");
    std::fs::write(&path, image).unwrap();
    let wb = Workbench::open(&dir.join("t.strata")).unwrap();
    let id = wb.add_evidence(&path.display().to_string()).unwrap().id;
    (wb, id)
}

fn done(wb: &Workbench, kind: JobKind, id: EvidenceId) -> String {
    match wb.run_step(kind, id).unwrap().state {
        JobState::Done(msg) => msg,
        other => panic!("{kind:?}: {other:?}"),
    }
}

fn wait(wb: &Workbench) {
    while wb.has_active_jobs() {
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn deleted_names(wb: &Workbench, id: EvidenceId, volume: u32) -> Vec<String> {
    let q = FileListQuery { evidence: id, volume, dir: None, filter: FileFilter::Deleted, name: String::new() };
    let list = wb.list_files(&q, Arc::default()).unwrap();
    (0..list.len()).filter_map(|i| list.row(i)).map(|r| r.name).collect()
}

#[test]
fn wiped_mbr_entry_volume_is_found_by_the_deep_scan() {
    let fat = FatVolume::new().file("notes.txt", b"plain notes").deleted_file("old wallet.dat", b"old wallet backup").finish();
    let at = 3 * MIB + 64 * 1024; // not on a probe point: only the deep scan sees it
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = case_with(dir.path(), &disk(16 * MIB, &[], &[(at, &fat)]));
    assert!(wb.evidence().unwrap()[0].volumes.is_empty());

    done(&wb, JobKind::IndexFiles, id);
    done(&wb, JobKind::Scan, id);
    let msg = done(&wb, JobKind::RecoverPartitions, id);
    assert!(msg.starts_with("1 deleted partitions"), "{msg}");

    let vols = wb.evidence().unwrap()[0].volumes.clone();
    assert_eq!(vols.len(), 1);
    assert_eq!((vols[0].range.start(), vols[0].fs.name()), (at as u64, "FAT16"));
    assert!(vols[0].label.starts_with("deleted partition"), "{}", vols[0].label);
    assert_eq!(deleted_names(&wb, id, vols[0].index), vec!["old wallet.dat"]);
    let named = wb.find_files_by_name("wallet", None, 10).unwrap();
    assert_eq!((named.len(), named[0].state.as_str()), (1, "Deleted"));
    // Running the step again changes nothing.
    done(&wb, JobKind::RecoverPartitions, id);
    assert_eq!(wb.evidence().unwrap()[0].volumes.len(), 1);
}

#[test]
fn ntfs_with_only_its_backup_boot_sector_is_recovered() {
    let mut ntfs = NtfsVolume::new().file("kept.txt", b"kept").deleted_file("gone.txt", b"bye").finish();
    ntfs[..512].fill(0);
    let at = 5 * MIB + 128 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = case_with(dir.path(), &disk(12 * MIB, &[], &[(at, &ntfs)]));
    assert!(wb.evidence().unwrap()[0].volumes.is_empty());
    done(&wb, JobKind::Scan, id);
    done(&wb, JobKind::RecoverPartitions, id);
    let vols = wb.evidence().unwrap()[0].volumes.clone();
    assert_eq!(vols.len(), 1, "{vols:?}");
    assert_eq!((vols[0].range.start(), vols[0].range.len(), vols[0].fs.name()), (at as u64, MIB as u64, "NTFS"));
    assert_eq!(deleted_names(&wb, id, 0), vec!["gone.txt"]);
}

const PHRASE: &str = "секретная фраза";

/// MBR partition at 1 MiB: a live file and a deleted one, both mentioning `needle`; the
/// deleted one also holds the phrase in UTF-16LE and CP1251.
fn searchable(dir: &Path) -> (Arc<Workbench>, EvidenceId, Vec<u8>) {
    let mut secret = b"needle; ".to_vec();
    secret.extend(Encoding::Utf16Le.encode(PHRASE).unwrap());
    secret.extend(b" and ");
    secret.extend(Encoding::Cp1251.encode(PHRASE).unwrap());
    let fat = FatVolume::new().file("live.txt", b"live needle here").deleted_file("secret.txt", &secret).finish();
    let (wb, id) = case_with(dir, &disk(8 * MIB, &[(0x06, MIB, fat.len())], &[(MIB, &fat)]));
    (wb, id, secret)
}

fn search(wb: &Arc<Workbench>, query: SearchQuery) -> Vec<SearchResultRow> {
    let (_, search) = wb.start_search(query, None).unwrap();
    wait(wb);
    let record = wb.search_record(search).unwrap().unwrap();
    assert_eq!(record.state, "done");
    wb.search_results(search, 0, 1000).unwrap()
}

#[test]
fn search_finds_encoded_phrase_in_a_deleted_file() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, _, secret) = searchable(dir.path());
    let query = SearchQuery {
        pattern: Pattern::Text("Секретная Фраза".into()),
        encodings: vec![Encoding::Utf8, Encoding::Utf16Le, Encoding::Cp1251],
        case_insensitive: true,
        scope: Scope::WholeDisk,
    };
    let rows = search(&wb, query);
    assert_eq!(rows.len(), 2, "{rows:?}");
    let utf16 = rows.iter().find(|r| r.encoding == "UTF-16LE").expect("utf-16 match");
    let cp1251 = rows.iter().find(|r| r.encoding == "CP1251").expect("cp1251 match");
    for r in [utf16, cp1251] {
        assert_eq!((r.file_path.as_deref(), r.file_state.as_deref(), r.location.as_str()), (Some("secret.txt"), Some("Deleted"), "deleted"));
        assert!(r.preview.contains(PHRASE), "{}", r.preview);
        let shown: String = r.preview.chars().skip(r.match_from as usize).take((r.match_to - r.match_from) as usize).collect();
        assert_eq!(shown, PHRASE);
    }
    assert_eq!(utf16.file_offset, Some(8));
    assert_eq!(cp1251.file_offset, Some((secret.len() - PHRASE.chars().count()) as u64));
}

#[test]
fn unallocated_scope_skips_live_files() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, _, _) = searchable(dir.path());
    let needle = |scope| SearchQuery { scope, ..SearchQuery::text("NEEDLE") };
    let states = |rows: Vec<SearchResultRow>| {
        let mut s: Vec<String> = rows.into_iter().map(|r| r.location).collect();
        s.sort();
        s
    };
    assert_eq!(states(search(&wb, needle(Scope::WholeDisk))), vec!["deleted", "live"]);
    assert_eq!(states(search(&wb, needle(Scope::Unallocated))), vec!["deleted"]);
    assert_eq!(states(search(&wb, needle(Scope::DeletedFiles))), vec!["deleted"]);
    assert_eq!(states(search(&wb, needle(Scope::Volume(0)))), vec!["deleted", "live"]);
}

#[test]
fn recovery_writes_files_log_and_flags_overwritten_ones() {
    let intact = b"deleted but intact".repeat(40);
    let fat = FatVolume::new()
        .file("keep.txt", b"live content")
        .deleted_file("intact.bin", &intact)
        .overwritten_file("old.doc", &[7u8; 1500], "new.txt", b"new data over old clusters")
        .finish();
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = case_with(dir.path(), &disk(8 * MIB, &[(0x06, MIB, fat.len())], &[(MIB, &fat)]));
    let root = FileListQuery { evidence: id, volume: 0, dir: None, filter: FileFilter::All, name: String::new() };
    let list = wb.list_files(&root, Arc::default()).unwrap();
    let all: Vec<usize> = (0..list.len()).filter_map(|i| list.row(i)).map(|r| r.index).collect();
    assert_eq!(all.len(), 4);

    let out = tempfile::tempdir().unwrap();
    wb.recover_files(id, 0, all.clone(), out.path().to_path_buf()).unwrap();
    wait(&wb);
    let job = wb.jobs().pop().unwrap();
    assert_eq!(job.state, JobState::Done("4 files recovered, 1 partial".into()));
    let base = out.path().join("disk.img").join("V0 FAT16");
    assert_eq!(std::fs::read(base.join("keep.txt")).unwrap(), b"live content");
    assert_eq!(std::fs::read(base.join("intact.bin")).unwrap(), intact);
    assert_eq!(std::fs::read(base.join("old.doc.partial")).unwrap().len(), 1500);
    let log = std::fs::read_to_string(out.path().join("recovery-log.csv")).unwrap();
    assert_eq!(log.lines().count(), 5, "{log}");
    let old = log.lines().find(|l| l.starts_with("old.doc,")).expect("logged");
    assert!(old.starts_with("old.doc,deleted,1500,"), "{old}");
    assert!(old.contains("overwritten") || old.contains("in use"), "{old}");

    // Never next to the evidence.
    wb.recover_files(id, 0, all, dir.path().join("out")).unwrap();
    wait(&wb);
    assert!(matches!(wb.jobs().pop().unwrap().state, JobState::Failed(_)));
}

#[test]
fn findings_export_carved_files_and_archive_members() {
    use strata_identify::testkit;
    use strata_workbench::{HitCategory, HitQuery};
    let note = b"old note kept in an archive, write to demo.user@example.org\n".to_vec();
    let zip = testkit::zip(&[("notes/old.txt", &note, true)]);
    let mut image = vec![0u8; 2 * MIB];
    image[0x10000..0x10000 + zip.len()].copy_from_slice(&zip);
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = case_with(dir.path(), &image);
    done(&wb, JobKind::Carve, id);
    done(&wb, JobKind::Archives, id);
    let out = tempfile::tempdir().unwrap();

    let all = wb.hits(&HitQuery { categories: vec![HitCategory::FileSignature], ..HitQuery::default() }).unwrap();
    let carved = all.iter().find(|h| h.hit.detector == "carve.unallocated").expect("carved zip");
    let written = wb.export_finding(carved, out.path()).unwrap();
    assert_eq!(std::fs::read(&written.written_to).unwrap(), zip);
    assert!(written.written_to.starts_with(out.path().canonicalize().unwrap().join("disk.img").join("$Carved")));

    let member = wb.hits(&HitQuery::default()).unwrap().into_iter().find(|h| h.file_path.as_deref().is_some_and(|p| p.ends_with("!/notes/old.txt")));
    let member = member.expect("a finding inside the member");
    let written = wb.export_finding(&member, out.path()).unwrap();
    assert_eq!(std::fs::read(&written.written_to).unwrap(), note);
    let log = std::fs::read_to_string(out.path().join("recovery-log.csv")).unwrap();
    assert_eq!(log.lines().count(), 3, "{log}");
}
