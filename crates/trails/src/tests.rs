//! Every fate on a synthetic two-disk case: traces from shortcuts, Prefetch, the registry and
//! downloads; file-table entries; wallet findings in files and free space; an archive and a
//! mail. All names, paths and values are made up.

use crate::*;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::{EventRecord, LeadRule};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};

const A: EvidenceId = EvidenceId::new(1);
const B: EvidenceId = EvidenceId::new(2);
const ADDR: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

fn event(id: i64, disk: EvidenceId, t: Timestamp, kind: EventKind, title: &str, detail: &str, artifact: &str) -> EventRecord {
    EventRecord { id, evidence: disk, event: TimelineEvent::new(t, kind, title, EventSource::new(artifact, "x")).with_detail(detail) }
}

fn lnk(id: i64, t: Timestamp, target: &str, size: u64) -> EventRecord {
    event(id, A, t, EventKind::DocumentOpened, target, &format!("first opened (LNK created); size {size}; volume 1A2B-3C4D 'DATA'"), "windows.lnk")
}

fn file(disk: EvidenceId, path: &str, size: u64, state: EntryState, created: Timestamp) -> FileRecord {
    FileRecord { evidence: disk, volume: 0, path: path.into(), size, state, created: Some(created), modified: Some(created), changed: None, sha256: None, detected_type: None }
}

fn hit(id: i64, disk: EvidenceId, path: Option<&str>, addresses: &[&str]) -> WalletHit {
    WalletHit {
        id,
        evidence: disk,
        category: HitCategory::Wallet,
        detector: if path.is_some() { "wallet.file" } else { "wallet.carved" }.into(),
        label: "Bitcoin Core wallet".into(),
        value: "1 keys, 1 addresses".into(),
        offset: 0x10_0000 * id as u64,
        volume: Some(0),
        file_path: path.map(str::to_string),
        file_state: path.map(|_| EntryState::Deleted),
        confidence: 1.0,
        addresses: addresses.iter().map(|a| a.to_string()).collect(),
        fingerprint: None,
        size: Some(98_304),
        has_records: true,
    }
}

fn find<'a>(trails: &'a [Trail], name: &str) -> &'a Trail {
    trails.iter().find(|t| t.name.eq_ignore_ascii_case(name)).unwrap_or_else(|| panic!("no trail for {name}: {:?}", trails.iter().map(|t| (&t.name, &t.origin)).collect::<Vec<_>>()))
}

fn case() -> TrailInputs {
    let mut i = TrailInputs::default();
    // Bitcoin installed, then a wallet that is still there.
    i.events.push(event(1, A, at(2011, 5, 3), EventKind::ProgramInstalled, "Bitcoin 0.3.21", "key last write", "registry.software").into_crypto());
    i.events.push(lnk(2, at(2011, 5, 4), "C:\\Documents and Settings\\Admin\\Application Data\\Bitcoin\\wallet.dat", 98_304));
    i.files.push(file(A, "Documents and Settings/Admin/Application Data/Bitcoin/wallet.dat", 98_304, EntryState::Live, at(2011, 5, 4)));
    // A deleted wallet whose content was still read.
    i.events.push(event(3, A, at(2011, 8, 1), EventKind::ProgramRun, "BITCOIN-QT.EXE", "prefetch v17, run count 2; files: \\DEVICE\\HARDDISKVOLUME1\\WORK\\BTC\\MINING-WALLET.DAT", "windows.prefetch"));
    i.files.push(file(A, "work/btc/mining-wallet.dat", 65_536, EntryState::Deleted, at(2011, 7, 20)));
    i.hits.push(hit(10, A, Some("work/btc/mining-wallet.dat"), &[ADDR]));
    // A deleted note nothing could be read from.
    i.files.push(file(A, "Documents and Settings/Admin/Desktop/privkey.txt", 120, EntryState::Deleted, at(2012, 1, 2)));
    // Moved: the shortcut names D:\old, the file sits in a backup folder on the other disk.
    i.events.push(lnk(4, at(2012, 3, 1), "D:\\old\\savings.wallet", 40_000));
    i.files.push(file(B, "backup/2012/savings.wallet", 40_000, EntryState::Live, at(2012, 4, 1)));
    // Only in an archive.
    i.events.push(lnk(5, at(2012, 6, 1), "C:\\keys\\cold.wallet", 5_000));
    i.members.push(ArchiveMember { evidence: B, archive_path: "dump/old.zip".into(), member_path: "dump/old.zip!/keys/cold.wallet".into(), size: Some(5_000), modified: Some(at(2012, 6, 2)), encrypted: true });
    // Only mailed.
    i.events.push(event(6, A, at(2013, 1, 5), EventKind::Download, "C:\\Downloads\\wallet-backup.zip", "from http://mail.example/att (777 bytes)", "chrome.history"));
    i.attachments.push(MailAttachment { message: 42, evidence: B, name: "wallet-backup.zip".into(), size: 777, at: Some(at(2013, 1, 4)), subject: "backup".into(), sender: "a@example.test".into() });
    // Carved: wallet records in free space, nothing else.
    i.hits.push(hit(11, B, None, &["1CarvedOnlyAddressXXXXXXXXXXXXXXXX"]));
    // Not found: a shortcut and a Recycle Bin record name a file no disk holds; a weak
    // database header lies in free space of the same disk.
    i.events.push(lnk(7, at(2014, 2, 1), "E:\\stash\\granny.wallet", 90_000));
    i.events.push(event(8, A, at(2014, 2, 9), EventKind::FileDeleted, "E:\\stash\\granny.wallet", "deleted to the Recycle Bin", "windows.recycle"));
    let mut weak = hit(12, A, None, &[]);
    (weak.label, weak.confidence, weak.has_records, weak.category) = ("Berkeley DB file".into(), 0.2, false, HitCategory::Wallet);
    i.hits.push(weak);
    // RecentDocs names only `wallet.dat`; it joins the one full path with that name.
    i.events.push(event(9, A, at(2011, 6, 1), EventKind::DocumentOpened, "wallet.dat", "RecentDocs", "registry.ntuser"));
    // Filesystem events never make traces of their own.
    i.events.push(event(13, A, at(2011, 5, 4), EventKind::FileCreated, "wallet.dat", "", "fs"));
    i
}

trait Crypto {
    fn into_crypto(self) -> Self;
}

impl Crypto for EventRecord {
    fn into_crypto(mut self) -> Self {
        self.event = self.event.with_tag(CRYPTO_TAG);
        self
    }
}

#[test]
fn every_fate() {
    let trails = TrailBuilder::new().build(&case());
    let live = find(&trails, "wallet.dat");
    assert_eq!(live.verdict.fate, Fate::Live, "{:#?}", live);
    assert_eq!(live.events().collect::<Vec<_>>(), [1, 2, 9], "install, shortcut and RecentDocs: {:#?}", live.steps);
    assert_eq!(live.steps[0].kind, StepKind::Installed, "the software comes first");

    let deleted = find(&trails, "mining-wallet.dat");
    assert_eq!(deleted.verdict.fate, Fate::Deleted { verified: true });
    assert_eq!(deleted.hits().collect::<Vec<_>>(), [10]);
    assert!(deleted.steps.iter().any(|s| s.kind == StepKind::Loaded && s.text.contains("BITCOIN-QT.EXE")));

    let note = find(&trails, "privkey.txt");
    assert_eq!(note.verdict.fate, Fate::Deleted { verified: false });
    assert!(note.hints.iter().any(|h| h.contains("Files screen")), "{:?}", note.hints);

    let moved = find(&trails, "savings.wallet");
    assert_eq!(moved.verdict.fate, Fate::Moved { live: true });
    assert!(moved.verdict.explanation[1].contains("same name and size") && moved.verdict.explanation[1].contains("backup/2012"), "{:?}", moved.verdict);
    assert_eq!(moved.evidence, [A, B], "spans both disks");

    let archived = find(&trails, "cold.wallet");
    assert_eq!(archived.verdict.fate, Fate::InArchive);
    assert!(archived.verdict.explanation[1].contains("encrypted"));

    let mailed = find(&trails, "wallet-backup.zip");
    assert_eq!(mailed.verdict.fate, Fate::InMail);
    assert!(mailed.steps.iter().any(|s| matches!(s.link, StepLink::Message { id: 42, .. })));

    let carved = trails.iter().find(|t| t.verdict.fate == Fate::Carved).expect("carved trail");
    assert!(carved.verdict.explanation.iter().any(|s| s.contains("free space")), "{:?}", carved.verdict);
    assert_eq!(carved.hits().collect::<Vec<_>>(), [11]);

    let lost = find(&trails, "granny.wallet");
    assert_eq!(lost.verdict.fate, Fate::NotFound);
    let hints = lost.hints.join(" ");
    assert!(hints.contains("drive E:") && hints.contains("1A2B-3C4D"), "{hints}");
    assert!(hints.contains("2014-02-01 to 2014-02-09"), "{hints}");
    assert!(hints.contains("Berkeley DB file at disk offset 0xc00000"), "the weak header is a candidate: {hints}");
    assert!(!trails.iter().any(|t| t.hits().any(|h| h == 12)), "a weak header is no trail of its own");
}

#[test]
fn same_content_links_a_renamed_copy() {
    let mut i = TrailInputs::default();
    i.events.push(lnk(1, at(2012, 1, 1), "C:\\btc\\wallet.dat", 1));
    i.files.push(file(A, "btc/wallet.dat", 98_304, EntryState::Deleted, at(2011, 12, 1)));
    i.hits.push(hit(1, A, Some("btc/wallet.dat"), &[ADDR]));
    let mut renamed = hit(2, B, Some("photos/IMG_0001.JPG"), &[ADDR]);
    renamed.file_state = Some(EntryState::Live);
    i.hits.push(renamed);
    let trails = TrailBuilder::new().build(&i);
    assert_eq!(trails.len(), 1, "{:?}", trails.iter().map(|t| &t.origin).collect::<Vec<_>>());
    let t = &trails[0];
    // The origin's entry is deleted but verified; the renamed live copy ranks better.
    assert_eq!(t.verdict.fate, Fate::Moved { live: true });
    assert!(t.verdict.explanation[1].contains("same wallet content"), "{:?}", t.verdict);
    assert!(t.verdict.confidence >= 0.9);
}

#[test]
fn trails_become_leads_and_rank() {
    let trails = TrailBuilder::new().build(&case());
    assert!(trails.windows(2).all(|w| w[0].score >= w[1].score));
    let live = find(&trails, "wallet.dat");
    let deleted = find(&trails, "mining-wallet.dat");
    assert!(deleted.score > live.score, "a recoverable deleted wallet outranks a live one");
    let lead = deleted.to_lead();
    assert_eq!(lead.rule, LeadRule::WalletTrail);
    assert!(lead.id.starts_with("trail:") && lead.hits().any(|h| h == 10));
    assert_eq!(describe_step(&live.steps[0]), "2011-05-03 Bitcoin 0.3.21 installed (registry.software)");
}
