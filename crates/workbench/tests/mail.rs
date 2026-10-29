//! The Mail step end to end on a synthetic disk: an mbox and `.eml` files in a FAT volume
//! (one deleted), and a piece of an mbox in space outside the volume. Messages are read from
//! the files, carved from free text, merged when found twice, and exported. Older cases get
//! the step queued when they open.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_fs::testkit::FatVolume;
use strata_workbench::{EvidenceId, JobKind, JobState, MessageQuery, MessageState, Workbench};

const MIB: usize = 1 << 20;
const FRAGMENT_AT: usize = 10 * MIB;

/// Lines of plain text, about `kib` KiB.
fn filler(kib: usize) -> String {
    "the quick brown fox jumps over the lazy dog, line of a long letter\r\n".repeat(kib * 1024 / 68 + 1)
}

fn eml(id: &str, date: &str, from: &str, subject: &str, body: &str) -> String {
    format!("Message-ID: <{id}>\r\nDate: {date}\r\nFrom: {from}\r\nTo: owner@example.com\r\nSubject: {subject}\r\n\r\n{body}")
}

fn with_attachment() -> String {
    "Message-ID: <note@example.com>\r\nDate: Mon, 3 Jan 2011 09:00:00 +0000\r\nFrom: friend@example.ru\r\nTo: owner@example.com\r\n\
Subject: your backup\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"zz\"\r\n\r\n--zz\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\nthe file you asked for\r\n--zz\r\nContent-Type: application/octet-stream; name=\"wallet.dat\"\r\n\
Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"wallet.dat\"\r\n\r\naGVsbG8gd2FsbGV0\r\n--zz--\r\n"
        .to_string()
}

fn image(dir: &Path) -> std::path::PathBuf {
    let inbox = format!(
        "From - Sat Jan 01 10:00:00 2011\r\n{}\r\n\r\nFrom - Sun Jan 02 10:00:00 2011\r\n{}\r\n",
        eml("one@example.com", "Sat, 1 Jan 2011 10:00:00 +0000", "shop@example.com", "order shipped", "your order is on its way"),
        eml("two@example.com", "Sun, 2 Jan 2011 10:00:00 +0000", "bank@example.ru", "statement", "balance attached"),
    );
    let old = eml("old@example.com", "Tue, 4 Jan 2011 08:00:00 +0000", "exchange@example.com", "withdrawal key", &filler(200));
    let fat = FatVolume::new()
        .file("notes.txt", filler(128).as_bytes())
        .deleted_file("old.eml", old.as_bytes())
        .file_in("Mail", "Inbox", inbox.as_bytes())
        .file("note.eml", with_attachment().as_bytes())
        .finish();
    // A piece of an mbox in space outside the volume: one message seen nowhere else, then a
    // copy of the live note.eml.
    let lost = eml("lost@example.com", "Wed, 5 Jan 2011 12:00:00 +0000", "miner@example.com", "pool payout", &filler(80));
    let fragment = format!("{lost}\r\n\r\nFrom - Mon Jan 03 09:00:00 2011\r\n{}", with_attachment());
    let mut disk = vec![0u8; 16 * MIB];
    let e = 446;
    disk[e + 4] = 0x06;
    disk[e + 8..e + 12].copy_from_slice(&((MIB / 512) as u32).to_le_bytes());
    disk[e + 12..e + 16].copy_from_slice(&((fat.len() / 512) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[MIB..MIB + fat.len()].copy_from_slice(&fat);
    disk[FRAGMENT_AT..FRAGMENT_AT + fragment.len()].copy_from_slice(fragment.as_bytes());
    let path = dir.join("disk.img");
    std::fs::write(&path, disk).unwrap();
    path
}

fn open(dir: &Path) -> (Arc<Workbench>, EvidenceId) {
    let img = image(dir);
    let wb = Workbench::open(&dir.join("t.strata")).unwrap();
    let id = wb.add_evidence(&img.display().to_string()).unwrap().id;
    (wb, id)
}

fn done(wb: &Workbench, kind: JobKind, id: EvidenceId) -> String {
    match wb.run_step(kind, id).unwrap().state {
        JobState::Done(msg) => msg,
        other => panic!("{kind:?}: {other:?}"),
    }
}

#[test]
fn reads_files_carves_free_space_and_merges_copies() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = open(dir.path());
    done(&wb, JobKind::IndexFiles, id);
    done(&wb, JobKind::Scan, id);
    let summary = done(&wb, JobKind::Mail, id);
    assert!(summary.starts_with("5 messages from 3 mail files"), "{summary}");

    let rows = wb.messages(&MessageQuery::default()).unwrap();
    let by_subject = |s: &str| rows.iter().find(|r| r.subject == s).unwrap_or_else(|| panic!("{s}: {rows:#?}"));
    assert_eq!(rows.len(), 5, "{rows:#?}");
    let shipped = by_subject("order shipped");
    assert_eq!((shipped.location.state, shipped.folder.as_str(), shipped.copies), (MessageState::Live, "Inbox", 0));
    assert_eq!(shipped.from, "shop@example.com");
    let old = by_subject("withdrawal key");
    assert_eq!((old.location.state, old.copies), (MessageState::Deleted, 1), "the deleted file and its carved clusters are one message");
    let note = by_subject("your backup");
    assert_eq!((note.location.state, note.copies, note.attachments), (MessageState::Live, 1, 1));
    let lost = by_subject("pool payout");
    assert_eq!((lost.location.state, lost.location.offset), (MessageState::Carved, FRAGMENT_AT as u64));
    assert!(lost.location.path.is_none());

    let full = wb.message(lost.id).unwrap().unwrap();
    assert!(full.message.body.contains("lazy dog"));
    assert!(!full.message.body.contains("your backup"), "the carved message ends where the next one starts");
    let note_full = wb.message(note.id).unwrap().unwrap();
    assert_eq!(note_full.places[0].state, MessageState::Carved);
    assert_eq!(note_full.message.attachments[0].name, "wallet.dat");

    let out = tempfile::tempdir().unwrap();
    let written = wb.export_attachment(note.id, 0, out.path()).unwrap();
    assert_eq!(std::fs::read(&written.written_to).unwrap(), b"hello wallet");
    assert!(wb.export_attachment(note.id, 5, out.path()).is_err());
    let eml = wb.export_message(lost.id, out.path()).unwrap();
    assert!(std::fs::read(&eml.written_to).unwrap().starts_with(b"Message-ID: <lost@example.com>"));
    assert!(wb.message_raw(old.id).unwrap().starts_with(b"Message-ID: <old@example.com>"));

    assert_eq!(wb.messages_with_address("OWNER@example.com", 100).unwrap().len(), 5);
    assert_eq!(wb.messages_with_address("bank@example.ru", 100).unwrap().len(), 1);
    let text = MessageQuery { text: Some("way".into()), ..MessageQuery::default() };
    assert_eq!(wb.message_count(&text).unwrap(), 1);

    // A second run starts afresh and stores the same.
    done(&wb, JobKind::Mail, id);
    assert_eq!(wb.message_count(&MessageQuery::default()).unwrap(), 5);
}

#[test]
fn without_a_disk_index_only_files_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, id) = open(dir.path());
    done(&wb, JobKind::IndexFiles, id);
    let summary = done(&wb, JobKind::Mail, id);
    assert!(summary.contains("0 carved"), "{summary}");
    assert_eq!(wb.message_count(&MessageQuery::default()).unwrap(), 4);
}

fn wait_idle(wb: &Workbench) {
    let until = Instant::now() + Duration::from_secs(120);
    while wb.has_active_jobs() {
        assert!(Instant::now() < until, "jobs did not finish: {:?}", wb.jobs());
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn older_cases_read_their_mail_when_opened() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("t.strata");
    let id = {
        let (wb, id) = open(dir.path());
        done(&wb, JobKind::IndexFiles, id);
        wb.case().set_setting("rules_version", "2").unwrap();
        id
    };
    let wb = Workbench::open(&case).unwrap();
    wait_idle(&wb);
    let mail: Vec<_> = wb.jobs().into_iter().filter(|j| j.kind == JobKind::Mail).collect();
    assert_eq!(mail.len(), 1, "{:?}", wb.jobs());
    assert!(matches!(mail[0].state, JobState::Done(_)), "{:?}", mail[0].state);
    assert!(!wb.jobs().iter().any(|j| j.kind == JobKind::Recheck), "version 2 cases were re-checked already");
    assert_eq!(wb.message_count(&MessageQuery { evidence: Some(id), ..MessageQuery::default() }).unwrap(), 4);
    drop(wb);

    // Opened again: nothing more to catch up on.
    let wb = Workbench::open(&case).unwrap();
    wait_idle(&wb);
    assert_eq!(wb.jobs().iter().filter(|j| j.kind == JobKind::Mail).count(), 1);

    // A version-1 case with a scanned disk gets the re-check, the artefacts re-run (version 6)
    // and the mail job.
    wb.run_step(JobKind::Scan, id).unwrap();
    wb.case().set_setting("rules_version", "1").unwrap();
    assert_eq!(wb.recheck_if_rules_changed().unwrap(), 3);
    wait_idle(&wb);
    let kinds: Vec<JobKind> = wb.jobs().iter().map(|j| j.kind).collect();
    assert!(kinds.contains(&JobKind::Recheck), "{kinds:?}");
    assert_eq!(kinds.iter().filter(|k| **k == JobKind::Mail).count(), 2);
}
