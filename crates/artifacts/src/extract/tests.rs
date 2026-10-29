use super::*;
use crate::results::IdentityKind;
use crate::sqlite::testutil::db_bytes;
use std::sync::Arc;
use strata_fs::{EntryState, FileTimes};
use strata_kernel::{ByteRange, Result, Timestamp};
use strata_source::{BlockSource, SourceInfo, SourceKind};
use strata_volume::FsKind;

/// Evidence-free source: every test file is resident.
struct NoSource;

impl BlockSource for NoSource {
    fn info(&self) -> SourceInfo {
        SourceInfo { kind: SourceKind::RawImage, label: "mem".into(), location: "mem".into(), len: 0, sector_size: 512 }
    }
    fn len(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    fn damage(&self) -> Vec<ByteRange> {
        Vec::new()
    }
}

/// In-memory stand-in for a parsed filesystem.
struct FakeFs {
    source: Arc<dyn BlockSource>,
    entries: Vec<FileEntry>,
}

impl FileSystem for FakeFs {
    fn kind(&self) -> FsKind {
        FsKind::Ntfs
    }
    fn source(&self) -> &Arc<dyn BlockSource> {
        &self.source
    }
    fn entries(&self) -> &[FileEntry] {
        &self.entries
    }
    fn unallocated(&self) -> Vec<ByteRange> {
        Vec::new()
    }
    fn damage(&self) -> &[Damage] {
        &[]
    }
}

const UNIX: i64 = 1_305_394_569;
const WEBKIT: i64 = (UNIX + 11_644_473_600) * 1_000_000;
const FT: u64 = 129_498_681_690_000_000;

fn file(path: &str, data: Vec<u8>, state: EntryState) -> FileEntry {
    let t = Timestamp::from_unix_secs(UNIX);
    FileEntry {
        name: path.rsplit('/').next().unwrap_or(path).to_string(),
        path: path.to_string(),
        parent: None,
        is_dir: false,
        size: data.len() as u64,
        state,
        times: FileTimes { created: t, modified: Timestamp::from_unix_secs(UNIX + 3600), accessed: t, changed: t },
        extents: Vec::new(),
        resident: Some(data),
        native_id: 0,
        streams: Vec::new(),
        damage: Vec::new(),
    }
}

fn fake_disk() -> FakeFs {
    let xp = "Documents and Settings/Admin";
    let history = db_bytes(&format!(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,
            last_visit_time INTEGER, hidden INTEGER);
         CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
         INSERT INTO urls VALUES(1,'https://mtgox.com/','Mt.Gox',1,0,{WEBKIT},0);
         INSERT INTO visits VALUES(1,1,{WEBKIT},0,1);"
    ));
    let login = db_bytes(&format!(
        "CREATE TABLE logins(origin_url TEXT, signon_realm TEXT, username_value TEXT, password_value BLOB, date_created INTEGER);
         INSERT INTO logins VALUES('http://shop.example.ua/','http://shop.example.ua/','olga.test1',x'0102',{UNIX});"
    ));
    let mut hive = crate::registry::hive_testutil::HiveBuilder::new();
    hive.key("Control Panel").key("Environment");
    hive.value("Software\\Bitcoin\\Bitcoin-Qt", "strDataDir", 1, &crate::registry::hive_testutil::sz("D:\\btc"));
    let index = crate::browser::index_dat_testutil::build(&[("Visited: Admin@http://bitcoin.org/", FT), ("Visited: Admin@http://x.org/", FT)]);
    let entries = vec![
        file(&format!("{xp}/Local Settings/Application Data/Google/Chrome/User Data/Default/History"), history.clone(), EntryState::Deleted),
        file(&format!("{xp}/Local Settings/Application Data/Google/Chrome/User Data/Default/Login Data"), login, EntryState::Allocated),
        file(&format!("{xp}/NTUSER.DAT"), hive.build(), EntryState::Allocated),
        file(&format!("{xp}/Local Settings/History/History.IE5/index.dat"), index, EntryState::Allocated),
        file(&format!("{xp}/Recent/wallet.dat.lnk"), crate::windows::build_lnk("D:\\wallet.dat", FT, 7, "D", "admin-pc"), EntryState::Allocated),
        file("WINDOWS/Prefetch/BITCOIN.EXE-0F1E2D3C.pf", crate::windows::build_prefetch(17, "BITCOIN.EXE", FT, 3, &["\\X\\WALLET.DAT"]), EntryState::Allocated),
        file("RECYCLER/S-1-5-21-1-2-3-1003/INFO2", crate::windows::build_info2(&[("C:\\keys.txt", FT, false)]), EntryState::Allocated),
        file("WINDOWS/system32/config/SecEvent.Evt", crate::windows::build_evt(&[(UNIX as u32, 528, "Security", &["Admin"])]), EntryState::Allocated),
        file(
            &format!("{xp}/Local Settings/Application Data/Microsoft/Internet Explorer/DOMStore/POFAU5IQ/ivan.test2mailru.webagent.mail[1].xml"),
            b"<root/>".to_vec(),
            EntryState::Orphan,
        ),
        file("$Orphans/History", history, EntryState::Orphan),
        file("Users/Bob/Documents/notes.txt", b"hello".to_vec(), EntryState::Allocated),
    ];
    FakeFs { source: Arc::new(NoSource), entries }
}

#[test]
fn extract_walks_live_and_deleted_artifacts() {
    let fs = fake_disk();
    let ex = ArtifactExtractor::default();
    assert_eq!(ex.select(&fs).len(), 9);
    let out = ex.extract(&fs);
    let by = |artifact: &str| out.events.iter().filter(|e| e.source().artifact == artifact).collect::<Vec<_>>();

    let chrome = by("chrome.history");
    assert!(chrome.iter().any(|e| e.source().path.starts_with("$Orphans/")), "orphan found by signature");
    let chrome: Vec<_> = chrome.into_iter().filter(|e| e.source().path.starts_with("Documents")).collect();
    assert!(!chrome.is_empty());
    assert!(chrome.iter().all(|e| e.source().deleted && e.actor() == Some("Admin")));
    assert!(chrome.iter().any(|e| e.is_crypto() && e.has_tag("Mt. Gox")));

    assert!(by("registry.ntuser").iter().any(|e| e.kind() == EventKind::WalletActivity));
    assert_eq!(by("ie.index_dat").len(), 2);
    assert!(by("windows.lnk").iter().any(|e| e.kind() == EventKind::DocumentOpened && e.title() == "D:\\wallet.dat"));
    assert!(by("windows.prefetch").iter().all(|e| e.is_crypto()));
    assert_eq!(by("windows.recycle_info2").len(), 1);
    assert_eq!(by("windows.evt")[0].kind(), EventKind::Login);

    let id = |v: &str| out.identities.iter().find(|i| i.value == v);
    assert_eq!(id("olga.test1").unwrap().kind, IdentityKind::Login);
    let wa = id("ivan.test2@mail.ru").unwrap();
    assert!(wa.first_seen < wa.last_seen);
    assert!(out.events.iter().any(|e| e.kind() == EventKind::AccountSeen && e.title() == "ivan.test2@mail.ru" && e.source().deleted));

    let only_bob = ArtifactExtractor::new(ProfileHints { users: vec!["bob".into()], ..Default::default() });
    assert!(only_bob.select(&fs).is_empty());
    let live_only = ArtifactExtractor::new(ProfileHints { include_deleted: false, ..Default::default() });
    assert_eq!(live_only.select(&fs).len(), 7);
}

#[test]
fn fs_events_are_lazy_and_tagged() {
    let fs = fake_disk();
    let all: Vec<_> = fs_events(&fs).collect();
    assert_eq!(all.len(), fs.entries.len() * 4);
    assert!(all.iter().any(|e| e.source().deleted && e.kind() == EventKind::MftChanged));
    assert!(all.iter().any(|e| e.title().ends_with("wallet.dat.lnk") && e.is_crypto()));
    assert!(all.iter().any(|e| e.actor() == Some("Bob")));
    assert_eq!(fs_events(&fs).take(3).count(), 3);
}

#[test]
fn parse_bytes_sniffs_carved_files() {
    let fs = fake_disk();
    let history = fs.entries[0].resident.clone().unwrap();
    let out = parse_bytes("carve_000123.bin", &history).unwrap();
    assert_eq!(out.events[0].source().artifact, "chrome.history");
    assert_eq!(out.events[0].source().path, "carve_000123.bin");
    let hive = fs.entries[2].resident.clone().unwrap();
    assert!(parse_bytes("x", &hive).unwrap().events.iter().any(|e| e.is_crypto()));
    assert!(parse_bytes("x", b"\x00\x01\x02 random").is_none());
    let lnk = fs.entries[4].resident.clone().unwrap();
    assert!(!parse_bytes("y", &lnk).unwrap().events.is_empty());
    let _ = parse_bytes("RECYCLER/x/INFO2", b"short");
    let _ = parse_bytes("$IABC.txt", &[1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn profile_names() {
    assert_eq!(profile_of("Documents and Settings/Admin/NTUSER.DAT").as_deref(), Some("Admin"));
    assert_eq!(profile_of("Users/Public/x.txt"), None);
    assert_eq!(profile_of("Users/Admin"), None);
    assert_eq!(profile_of("WINDOWS/system32/config/SAM"), None);
}

#[test]
fn random_bytes_behind_every_signature_never_panic() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut noise = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 24) as u8
            })
            .collect()
    };
    let prefixes: Vec<Vec<u8>> = vec![
        crate::sqlite::MAGIC.to_vec(),
        b"regf".to_vec(),
        b"Client UrlCache MMF Ver 5.2\0".to_vec(),
        crate::windows::build_lnk("C:\\a", FT, 1, "", "m")[..0x4C].to_vec(),
        [17u32.to_le_bytes().as_slice(), b"SCCA"].concat(),
        [0x30u32.to_le_bytes().as_slice(), b"LfLe"].concat(),
        vec![0xCF, 0xAD, 0x12, 0xFE],
        b"From x\nFrom: a@b.cd\nSubject: s\n".to_vec(),
        b"<typed_history_item content=\"".to_vec(),
    ];
    for round in 0..40 {
        for (i, p) in prefixes.iter().enumerate() {
            let mut data = p.clone();
            data.extend(noise(64 + round * 397 + i * 31));
            let _ = parse_bytes("carved", &data);
        }
        for hint in ["INFO2", "$IXYZ.txt", "logins.json", "global_history.dat", "History"] {
            let _ = parse_bytes(hint, &noise(round * 211));
        }
    }
}
