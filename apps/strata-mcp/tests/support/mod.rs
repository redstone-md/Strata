//! A small synthetic case for the server tests: two blank disk images, a few findings, events,
//! file entries, one stored search and on-chain data. All values are made up.

use std::path::{Path, PathBuf};
use strata_case::{Attribution, FileRef, SearchResultRow};
use strata_chain::{AddressBalance, AddressHistory, AddressTx};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Timestamp};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};
use strata_workbench::Workbench;

pub const ADDR: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
pub const WIF: &str = "5KsyntheticTestKeyNotRealXXXXXXXXXXXXXXXXXXXXXXXXXX";
pub const WALLET: &str = "Documents and Settings/a/Application Data/Bitcoin/wallet.dat";

pub fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

fn blank_image(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, vec![0u8; 1 << 20]).unwrap();
    path.display().to_string()
}

fn in_file(path: &str, state: EntryState) -> Attribution {
    Attribution { volume: Some(0), file: Some(FileRef { path: path.into(), state, file_offset: 16 }) }
}

fn hit(detector: &str, category: HitCategory, label: &str, value: &str, confidence: f32) -> Hit {
    Hit::new(detector, category, 4096, value.len()).label(label).value(value).confidence(Confidence::new(confidence))
}

fn event(t: Timestamp, kind: EventKind, title: &str, artifact: &str) -> TimelineEvent {
    TimelineEvent::new(t, kind, title, EventSource::new(artifact, "Users/a/AppData/History")).with_tag(CRYPTO_TAG)
}

/// Build the case under `dir` and return the case folder.
pub fn synthetic_case(dir: &Path) -> PathBuf {
    let root = dir.join("synthetic.strata");
    let wb = Workbench::open_idle(&root).unwrap();
    let laptop = wb.add_evidence(&blank_image(dir, "laptop.img")).unwrap().id;
    let usb = wb.add_evidence(&blank_image(dir, "usb.img")).unwrap().id;
    let case = wb.case();

    let key = hit("crypto.wif", HitCategory::PrivateKey, "WIF private key", WIF, 0.8).details(serde_json::json!({"addresses": {"p2pkh": ADDR}}));
    let login = hit("accounts.login", HitCategory::Identity, "login (url)", "gox_tester", 0.8)
        .details(serde_json::json!({"service": "Mt. Gox", "service_id": "mtgox"}));
    let noise = hit("crypto.hex", HitCategory::PrivateKey, "raw hex key", "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff", 0.1);
    let renamed = hit("identify.mismatch", HitCategory::FileSignature, "ZIP archive named .jpg", "photo.jpg", 0.6);
    case.store_hits(
        laptop,
        &[
            (key, in_file(WALLET, EntryState::Deleted)),
            (hit("crypto.address", HitCategory::Address, "Bitcoin address", ADDR, 0.8), in_file(WALLET, EntryState::Deleted)),
            (login, Attribution::default()),
            (noise, Attribution::default()),
            (renamed, in_file("Users/a/Pictures/photo.jpg", EntryState::Allocated)),
        ],
    )
    .unwrap();
    case.store_hits(usb, &[(hit("crypto.address", HitCategory::Address, "Bitcoin address", ADDR, 0.8), Attribution::default())]).unwrap();

    case.store_events(
        laptop,
        &[
            event(at(2011, 6, 14), EventKind::UrlVisited, "http://freebitcoins.appspot.com/", "chrome.history"),
            event(at(2011, 11, 2), EventKind::AccountSeen, "gox_tester @ mtgox.com", "chrome.history"),
            event(at(2012, 2, 1), EventKind::UrlVisited, "https://mtgox.com/trade", "chrome.history"),
            TimelineEvent::new(at(2012, 2, 1), EventKind::FileCreated, "wallet.dat", EventSource::new("fs.ntfs", WALLET)),
        ],
    )
    .unwrap();

    case.store_balance(&AddressBalance { address: ADDR.into(), funded_sat: 5_000_000, spent_sat: 0, tx_count: 1, mempool_delta_sat: 0, source: "mock".into() }).unwrap();
    let tx = AddressTx { txid: "t1".into(), time: Some(at(2011, 6, 14)), received_sat: 5_000_000, sent_sat: 0 };
    case.store_history(&AddressHistory { address: ADDR.into(), txs: vec![tx], tx_count: 1, total_received_sat: 5_000_000, complete: true, source: "mock".into() })
        .unwrap();

    let search = case.begin_search("{\"text\":\"bitcoin\"}", "\"bitcoin\"").unwrap();
    case.store_search_results(&[SearchResultRow {
        search_id: search,
        evidence: laptop,
        offset: 8192,
        len: 7,
        encoding: "ASCII".into(),
        context: b"my bitcoin key".to_vec(),
        context_start: 8189,
        preview: "my bitcoin key".into(),
        match_from: 3,
        match_to: 10,
        volume: None,
        file_path: None,
        file_state: None,
        file_offset: None,
        location: "unallocated".into(),
    }])
    .unwrap();
    case.finish_search(search, "done", false).unwrap();
    wb.rebuild_insights().unwrap();
    drop(wb);

    let db = rusqlite::Connection::open(root.join("case.db")).unwrap();
    for (idx, path, state, ty, renamed) in [
        (1, WALLET, "Deleted", Some("Berkeley DB"), false),
        (2, "Users/a/Pictures/photo.jpg", "Allocated", Some("ZIP archive"), true),
        (3, "Users/a/notes.txt", "Allocated", None, false),
    ] {
        let name = path.rsplit('/').next().unwrap_or(path);
        db.execute(
            "INSERT INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, created, modified, detected_type, extension_mismatch)
             VALUES (?1, 0, ?2, ?3, ?4, 4096, 0, ?5, ?6, ?6, ?7, ?8)",
            rusqlite::params![laptop.get(), idx, path, name, state, at(2012, 2, 1).unix_secs(), ty, renamed],
        )
        .unwrap();
    }
    root
}

/// Every row of every table, to prove the server left the case as it found it.
pub fn dump(root: &Path) -> Vec<String> {
    let db = rusqlite::Connection::open_with_flags(root.join("case.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut out = Vec::new();
    for t in tables {
        let mut stmt = db.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let n = stmt.column_count();
        let rows = stmt
            .query_map([], |r| Ok((0..n).map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).ok())).collect::<Vec<_>>().join("|")))
            .unwrap();
        out.extend(rows.map(|r| format!("{t}: {}", r.unwrap())));
    }
    out
}
