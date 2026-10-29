//! The reads behind wallet trails on a synthetic case: what is picked up, what is left out.

use crate::{Attribution, Case, FileRef};
use rusqlite::params;
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, EvidenceId, Timestamp};
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_trails::{Fate, TrailBuilder};

const ADDR: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

fn case_with_disk(dir: &std::path::Path) -> (Case, EvidenceId) {
    let img = dir.join("zero.img");
    std::fs::write(&img, vec![0u8; 1 << 20]).unwrap();
    let case = Case::open(&dir.join("t.strata")).unwrap();
    let id = case.add_evidence(&img.display().to_string()).unwrap().id;
    (case, id)
}

fn ts(s: i64) -> Timestamp {
    Timestamp::from_unix_secs(s).unwrap()
}

fn add_file(case: &Case, disk: EvidenceId, idx: i64, path: &str, state: &str, detected: Option<&str>) {
    let name = path.rsplit('/').next().unwrap();
    case.with_write(|c| {
        c.execute(
            "INSERT INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, created, modified, detected_type)
             VALUES (?1, 0, ?2, ?3, ?4, 4096, 0, ?5, 1300000000, 1310000000, ?6)",
            params![disk.get(), idx, path, name, state, detected],
        )
    })
    .unwrap();
}

#[test]
fn reads_what_trails_link() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    let wallet = "Users/a/AppData/Roaming/Bitcoin/wallet.dat";
    add_file(&case, disk, 1, wallet, "Deleted", None);
    add_file(&case, disk, 2, "Users/a/Desktop/Кошелёк.txt", "Allocated", None);
    add_file(&case, disk, 3, "Users/a/Pictures/holiday.jpg", "Allocated", Some("Bitcoin Core wallet (Berkeley DB)"));
    add_file(&case, disk, 4, "Program Files/App/wallet.dll", "Allocated", None);
    add_file(&case, disk, 5, "Users/a/Desktop/notes.txt", "Allocated", None);
    add_file(&case, disk, 6, "Users/a/Desktop/readme.txt", "Allocated", None);

    let wallet_hit = Hit::new("wallet.file", HitCategory::Wallet, 4096, 4096)
        .label("Bitcoin Core wallet")
        .value("1 keys, 1 addresses")
        .confidence(Confidence::CERTAIN)
        .details(serde_json::json!({"addresses": [ADDR], "key_count": 1}));
    let seed = Hit::new("crypto.mnemonic", HitCategory::Mnemonic, 9000, 80).label("BIP39 seed").value("synthetic seed words").confidence(Confidence::HIGH);
    let weak = Hit::new("crypto.hex_key", HitCategory::PrivateKey, 9500, 64).value("synthetic-hex").confidence(Confidence::new(0.2));
    let carved = Hit::new("crypto.bdb_wallet", HitCategory::Wallet, 1 << 19, 4096)
        .label("Berkeley DB file")
        .value("bdb@0x80000")
        .confidence(Confidence::new(0.2))
        .details(serde_json::json!({"estimated_size": 970752, "wallet_records": []}));
    let in_file = |path: &str, state| Attribution { volume: Some(0), file: Some(FileRef { path: path.into(), state, file_offset: 0 }) };
    case.store_hits(
        disk,
        &[
            (wallet_hit, in_file(wallet, EntryState::Deleted)),
            (seed, in_file("Users/a/Desktop/notes.txt", EntryState::Allocated)),
            (weak, in_file("Users/a/Desktop/readme.txt", EntryState::Allocated)),
            (carved, Attribution::default()),
        ],
    )
    .unwrap();

    let ev = |kind, title: &str, detail: &str, artifact: &str| TimelineEvent::new(ts(1_305_000_000), kind, title, EventSource::new(artifact, "p")).with_detail(detail);
    case.store_events(
        disk,
        &[
            ev(EventKind::DocumentOpened, r"C:\Users\a\Desktop\notes.txt", "first opened (LNK created)", "windows.lnk"),
            ev(EventKind::FileCreated, r"C:\Users\a\AppData\Roaming\Bitcoin\wallet.dat", "LNK target times; size 4096", "windows.lnk"),
            ev(EventKind::FileCreated, r"C:\Users\a\Desktop\holiday.jpg", "LNK target times", "windows.lnk"),
            ev(EventKind::FileCreated, "Users/a/AppData/Roaming/Bitcoin/wallet.dat", "", "fs"),
            ev(EventKind::UrlVisited, "https://example.com/wallet.dat", "", "chrome.history"),
        ],
    )
    .unwrap();
    case.with_write(|c| {
        c.execute(
            "INSERT INTO archive_members (evidence_id, archive_path, member_path, depth, size, packed, recovered, encrypted, extension_mismatch, modified, damage)
             VALUES (?1, 'b.zip', 'b.zip!/keys/old.wallet', 1, 100, 50, 100, 0, 0, NULL, '[]'),
                    (?1, 'b.zip', 'b.zip!/docs/report.doc', 1, 100, 50, 100, 0, 0, NULL, '[]')",
            [disk.get()],
        )?;
        c.execute(
            "INSERT INTO messages (evidence_id, fingerprint, state, container, folder, offset, len, at, sender, recipients, subject, body, attachments, data, places)
             VALUES (?1, 'f1', 'Live', 'mbox', 'INBOX', 0, 10, 1306000000, 'a@example.test', '[]', 'keys', '', 2, ?2, '[]')",
            params![disk.get(), serde_json::json!({"attachments": [{"name": "wallet-backup.zip", "size": 777}, {"name": "photo.jpg", "size": 5}]}).to_string()],
        )
    })
    .unwrap();

    let inputs = case.trail_inputs().unwrap();
    let mut paths: Vec<&str> = inputs.files.iter().map(|f| f.path.as_str()).collect();
    paths.sort();
    assert_eq!(paths, ["Users/a/AppData/Roaming/Bitcoin/wallet.dat", "Users/a/Desktop/notes.txt", "Users/a/Desktop/Кошелёк.txt", "Users/a/Pictures/holiday.jpg"]);
    assert_eq!(inputs.hits.len(), 3, "the weak hex key stays out");
    let w = inputs.hits.iter().find(|h| h.category == HitCategory::Wallet && h.file_path.is_some()).unwrap();
    assert!(w.has_records && w.addresses == [ADDR] && w.file_state == Some(strata_trails::EntryState::Deleted));
    assert_eq!(inputs.hits.iter().find(|h| h.file_path.is_none()).unwrap().size, Some(970_752));
    assert_eq!(inputs.events.len(), 2, "artefact events naming wallet files or wallet software only: {:?}", inputs.events.iter().map(|e| e.event.title()).collect::<Vec<_>>());
    assert_eq!(inputs.members.len(), 1);
    assert_eq!(inputs.attachments.len(), 1);
    assert_eq!(inputs.attachments[0].at, Some(ts(1_306_000_000)));

    let trails = TrailBuilder::new().build(&inputs);
    let fate = |name: &str| trails.iter().find(|t| t.name == name).map(|t| t.verdict.fate);
    assert_eq!(fate("wallet.dat"), Some(Fate::Deleted { verified: true }));
    assert_eq!(fate("notes.txt"), Some(Fate::Live), "a file holding a seed that a shortcut names");
    assert_eq!(fate("old.wallet"), Some(Fate::InArchive));
    assert_eq!(fate("wallet-backup.zip"), Some(Fate::InMail));
}
