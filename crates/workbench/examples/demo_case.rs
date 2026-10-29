//! `cargo run -p strata-workbench --example demo_case -- <dir>`: build a case of synthetic
//! findings, events and chain histories (two blank disk images, no real evidence) for UI work
//! on the Leads, Accounts and Connections screens.

use std::path::Path;
use strata_case::{Attribution, FileRef, FoundMessage, MessageLocation, MessageState};
use strata_chain::{AddressBalance, AddressHistory, AddressTx};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Timestamp};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};
use strata_workbench::{MailContainer, Message, Workbench};

const A1: &str = "1DemoWa11etAddrAAAAAAAAAAAAAAAAAAA";
const A2: &str = "1DemoWa11etAddrBBBBBBBBBBBBBBBBBBB";
const A3: &str = "1DemoKeyFi1eAddrCCCCCCCCCCCCCCCCCC";
const A4: &str = "1DemoLooseAddrDDDDDDDDDDDDDDDDDDDD";

fn at(y: i64, m: i64, d: i64, h: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, h, 0, 0).expect("valid demo date")
}

fn blank_image(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, vec![0u8; 1 << 20]).expect("write blank image");
    path.display().to_string()
}

fn in_file(path: &str, state: EntryState) -> Attribution {
    Attribution { volume: Some(0), file: Some(FileRef { path: path.into(), state, file_offset: 0 }) }
}

fn hit(detector: &str, category: HitCategory, label: &str, value: &str, details: serde_json::Value) -> Hit {
    Hit::new(detector, category, 4096, value.len()).label(label).value(value).confidence(Confidence::HIGH).details(details)
}

fn identity(value: &str, service: &str, kind: &str, detail: &str, seen: Timestamp) -> Hit {
    let record = serde_json::json!({"kind": kind, "value": value, "service": service, "source": "", "first_seen": seen, "last_seen": seen, "detail": detail, "weak": false});
    hit("artifacts.identity", HitCategory::Identity, if kind == "Email" { "e-mail (artefact)" } else { "login" }, &value.to_lowercase(), record)
}

fn mail(n: u32, from: &str, to: &str, subject: &str, body: &str) -> FoundMessage {
    let raw = format!("Message-ID: <demo{n}@example.com>
Date: Mon, 2{n} Feb 2012 10:00:00 +0000
From: {from}
To: {to}
Subject: {subject}

{body}
");
    let path = "Users/demo/AppData/Roaming/Thunderbird/Profiles/x.default/Mail/Inbox";
    let location = MessageLocation { state: MessageState::Live, container: MailContainer::Mbox, volume: Some(0), file_idx: None, path: Some(path.into()), offset: n as u64 * 4096, len: raw.len() as u64 };
    FoundMessage { location, folder: "Inbox".into(), message: Message::parse(raw.as_bytes()).expect("demo message parses") }
}

fn event(t: Timestamp, kind: EventKind, title: &str, artifact: &str) -> TimelineEvent {
    TimelineEvent::new(t, kind, title, EventSource::new(artifact, "Users/demo/AppData")).with_tag(CRYPTO_TAG)
}

fn history(address: &str, txs: &[(Timestamp, u64, u64)]) -> AddressHistory {
    AddressHistory {
        address: address.into(),
        txs: txs.iter().enumerate().map(|(i, (t, r, s))| AddressTx { txid: format!("demo-{address}-{i}"), time: Some(*t), received_sat: *r, sent_sat: *s }).collect(),
        tx_count: txs.len() as u64,
        total_received_sat: txs.iter().map(|t| t.1).sum(),
        complete: true,
        source: "synthetic".into(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).ok_or("usage: demo_case <dir>")?);
    std::fs::create_dir_all(&dir)?;
    let wb = Workbench::open(&dir.join("demo.strata"))?;
    let laptop = wb.add_evidence(&blank_image(&dir, "laptop-2012.img"))?.id;
    let usb = wb.add_evidence(&blank_image(&dir, "backup-usb.img"))?.id;
    let case = wb.case();

    let wallet = "Documents and Settings/demo/Application Data/Bitcoin/wallet.dat";
    let keys = "Documents and Settings/demo/My Documents/keys.txt";
    let seed = "Users/demo/Documents/electrum seed.txt";
    case.store_hits(laptop, &[
        (hit("wallet.file", HitCategory::Wallet, "Bitcoin Core wallet (encrypted)", "2 keys, 2 addresses", serde_json::json!({"addresses": [A1, A2]})), in_file(wallet, EntryState::Deleted)),
        (hit("crypto.wif", HitCategory::PrivateKey, "WIF private key", "5KdemoSyntheticPrivateKeyNotRealXXXXXXXXXXXXXXXXXXX", serde_json::json!({"addresses": {"p2pkh": A3}})), in_file(keys, EntryState::Allocated)),
        (hit("crypto.mnemonic", HitCategory::Mnemonic, "Electrum seed (12 words)", "demo synthetic words only for the user interface", serde_json::json!({"type": "electrum", "words": 12})), in_file(seed, EntryState::Allocated)),
        (hit("crypto.address", HitCategory::Address, "Bitcoin address", A4, serde_json::Value::Null), Attribution::default()),
        (identity("gox_tester", "mtgox.com", "Login", "saved browser login", at(2011, 11, 2, 19)), in_file("Users/demo/AppData/Local/Google/Chrome/User Data/Default/Login Data", EntryState::Allocated)),
        (identity("olga.test1@yandex.ru", "btc-e.com", "Email", "saved browser login", at(2013, 3, 4, 21)), in_file("Users/demo/AppData/Local/Google/Chrome/User Data/Default/Login Data", EntryState::Allocated)),
        (identity("miner_test_1", "BTC Guild", "Login", "mining pool login (worker miner_test_1.rig)", at(2012, 7, 1, 10)), in_file("Program Files/cgminer/cgminer.conf", EntryState::Allocated)),
        (identity("anna.test3@mail.ru", "Mail.ru", "Email", "mail identity (prefs.js)", at(2010, 9, 1, 9)), in_file("Users/demo/AppData/Roaming/Thunderbird/Profiles/x.default/prefs.js", EntryState::Allocated)),
        (hit("accounts.login", HitCategory::Identity, "login", "olga_btc", serde_json::json!({"service": "BTC-e"})), in_file(keys, EntryState::Allocated)),
        (hit("accounts.email", HitCategory::Identity, "e-mail", "maintainer.test@example.org", serde_json::Value::Null), in_file("Windows/System32/drivers/etc/readme.txt", EntryState::Allocated)),
        (hit("accounts.url", HitCategory::Url, "Bitcointalk", "https://bitcointalk.org/index.php?action=profile;u=424242", serde_json::json!({"service": "Bitcointalk"})), Attribution::default()),
        (hit("accounts.url", HitCategory::Url, "FreeBitco.in", "https://freebitco.in/?op=home", serde_json::json!({"service": "FreeBitco.in"})), Attribution::default()),
    ])?;
    case.store_hits(usb, &[
        (hit("crypto.address", HitCategory::Address, "Bitcoin address", A1, serde_json::Value::Null), Attribution::default()),
        (hit("accounts.login", HitCategory::Identity, "login (url)", "gox_tester", serde_json::json!({"service": "Mt. Gox", "service_id": "mtgox"})), Attribution::default()),
    ])?;

    let db = rusqlite::Connection::open(dir.join("demo.strata").join("case.db"))?;
    for (idx, path, state, created, modified) in [
        (1, wallet, "Deleted", at(2011, 5, 1, 9), at(2012, 3, 2, 18)),
        (2, keys, "Allocated", at(2013, 4, 30, 22), at(2013, 4, 30, 22)),
        (3, seed, "Allocated", at(2014, 1, 10, 8), at(2014, 1, 10, 8)),
    ] {
        let name = path.rsplit('/').next().unwrap_or(path);
        db.execute(
            "INSERT OR REPLACE INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, created, modified) VALUES (?1, 0, ?2, ?3, ?4, 4096, 0, ?5, ?6, ?7)",
            rusqlite::params![laptop.get(), idx, path, name, state, created.unix_secs(), modified.unix_secs()],
        )?;
    }

    let mut events = vec![
        event(at(2011, 6, 14, 10), EventKind::UrlVisited, "http://freebitcoins.appspot.com/", "firefox.places"),
        event(at(2011, 6, 14, 11), EventKind::ProgramRun, "C:\\Program Files\\Bitcoin\\bitcoin-qt.exe", "windows.prefetch"),
        event(at(2011, 11, 2, 19), EventKind::AccountSeen, "gox_tester @ mtgox.com", "chrome.login_data"),
        event(at(2012, 2, 20, 15), EventKind::UrlVisited, "https://mtgox.com/trade/funding-options", "chrome.history"),
        event(at(2012, 7, 1, 10), EventKind::ProgramRun, "C:\\Program Files\\cgminer\\cgminer.exe", "windows.prefetch"),
        event(at(2013, 3, 4, 21), EventKind::UrlVisited, "https://btc-e.com/profile", "chrome.history"),
        event(at(2013, 5, 2, 20), EventKind::UrlVisited, "https://btc-e.com/exchange/btc_usd", "chrome.history"),
        event(at(2014, 1, 9, 20), EventKind::Download, "C:\\Users\\demo\\Downloads\\electrum-1.9.7-setup.exe", "chrome.history"),
        event(at(2014, 1, 9, 20), EventKind::Search, "electrum wallet download", "chrome.history"),
    ];
    for (m, d) in [(11, 20), (12, 15), (1, 10), (3, 1)] {
        let y = if m >= 11 { 2011 } else { 2012 };
        events.push(event(at(y, m, d, 12), EventKind::UrlVisited, "https://mtgox.com/", "chrome.history"));
    }
    for d in 0..7 {
        events.push(event(at(2015, 3, 1 + d * 3, 9), EventKind::UrlVisited, "https://freebitco.in/?op=home", "chrome.history"));
    }
    case.store_events(laptop, &events)?;
    case.store_events(usb, &[event(at(2012, 3, 1, 14), EventKind::UrlVisited, "https://mtgox.com/", "ie.index_dat")])?;

    let histories = [
        history(A1, &[(at(2011, 6, 14, 12), 5_000_000, 0), (at(2012, 1, 5, 12), 0, 2_000_000)]),
        history(A2, &[(at(2012, 2, 20, 16), 120_000_000, 0), (at(2012, 3, 1, 14), 0, 120_000_000)]),
        history(A3, &[(at(2013, 5, 2, 21), 30_000_000, 0)]),
        history(A4, &[(at(2016, 1, 1, 0), 1_000, 0)]),
    ];
    for h in &histories {
        let spent: u64 = h.txs.iter().map(|t| t.sent_sat).sum();
        case.store_balance(&AddressBalance { address: h.address.clone(), funded_sat: h.total_received_sat, spent_sat: spent, tx_count: h.tx_count, mempool_delta_sat: 0, source: "synthetic".into() })?;
        case.store_history(h)?;
    }
    let me = "anna.test3@mail.ru";
    let letters = [
        mail(1, "ivan.test2@example.ru", me, "the wallet", "Did you back up the wallet.dat from the old laptop?"),
        mail(2, me, "ivan.test2@example.ru", "re: the wallet", &format!("Yes, and the coins went to {A3} last spring.")),
        mail(3, "ivan.test2@example.ru", me, "pool payout", "BTC Guild paid out again."),
        mail(4, "support@btc-e.com", me, "BTC-e: confirm your registration", "Your login is olga_btc."),
    ];
    case.write(|w| w.messages(laptop, &letters))?;
    let (accounts, leads) = wb.rebuild_insights()?;
    println!("{}: {accounts} accounts, {leads} leads", dir.join("demo.strata").display());
    Ok(())
}
