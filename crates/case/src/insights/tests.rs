use crate::{Attribution, Case, FileRef};
use strata_accounts::{AccountResolver, AccountSource, IdentifierKind, Observation, SourceRef};
use strata_chain::{AddressBalance, AddressHistory, AddressTx};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::{Lead, LeadRef, LeadRule};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};

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

#[test]
fn key_findings_carry_file_times_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    let path = "Documents and Settings/a/Application Data/Bitcoin/wallet.dat";
    let key = Hit::new("crypto.wif", HitCategory::PrivateKey, 4096, 52)
        .label("WIF private key")
        .value("synthetic-wif")
        .confidence(strata_kernel::Confidence::HIGH)
        .details(serde_json::json!({"addresses": {"p2pkh": ADDR}}));
    let lone = Hit::new("crypto.address", HitCategory::Address, 9000, 34).value("1OtherAddressWithoutHistoryXXXXXX").confidence(strata_kernel::Confidence::HIGH);
    let file = FileRef { path: path.into(), state: EntryState::Deleted, file_offset: 0 };
    case.store_hits(disk, &[(key, Attribution { volume: Some(0), file: Some(file) }), (lone, Attribution::default())]).unwrap();
    case.with_conn(|c| {
        c.execute(
            "INSERT INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, created, modified)
             VALUES (?1, 0, 7, ?2, 'wallet.dat', 4096, 0, 'Deleted', 1300000000, 1310000000)",
            rusqlite::params![disk.get(), path],
        )
    })
    .unwrap();

    let found = case.key_findings(0.0).unwrap();
    assert_eq!(found.len(), 1, "addresses without history stay out");
    let k = &found[0];
    assert!(k.deleted && k.addresses == [ADDR]);
    assert_eq!((k.file_created, k.file_modified), (Some(ts(1_300_000_000)), Some(ts(1_310_000_000))));

    let balance = AddressBalance { address: ADDR.into(), funded_sat: 10, spent_sat: 0, tx_count: 1, mempool_delta_sat: 0, source: "mock".into() };
    case.store_balance(&balance).unwrap();
    assert_eq!(case.addresses_without_history().unwrap(), [ADDR]);
    let tx = AddressTx { txid: "t1".into(), time: Some(ts(1_305_000_000)), received_sat: 10, sent_sat: 0 };
    let history = AddressHistory { address: ADDR.into(), txs: vec![tx], tx_count: 1, total_received_sat: 10, complete: true, source: "mock".into() };
    case.store_history(&history).unwrap();
    assert!(case.addresses_without_history().unwrap().is_empty());
    assert_eq!(case.history_of(ADDR).unwrap(), Some(history.clone()));
    assert_eq!(case.histories().unwrap(), [history]);
}

#[test]
fn accounts_leads_and_lead_events_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    let mut r = AccountResolver::new();
    r.observe(Observation {
        service: Some("mtgox.com".into()),
        identifier: "gox_tester".into(),
        kind: IdentifierKind::Login,
        source: AccountSource { evidence: disk, origin: SourceRef::Hit(1), detail: "saved browser login".into(), at: Some(ts(1_310_000_000)) },
        first_seen: None,
        last_seen: None,
        confidence: 0.8,
    });
    let accounts = r.finish();
    assert_eq!(case.replace_accounts(&accounts).unwrap(), 1);
    assert_eq!(case.accounts().unwrap(), accounts);
    assert_eq!(case.replace_accounts(&[]).unwrap(), 0);
    assert!(case.accounts().unwrap().is_empty());

    let lead = |id: &str, score: f32| Lead {
        id: id.into(),
        rule: LeadRule::AccountCheck,
        title: id.into(),
        explanation: vec!["x".into()],
        score,
        refs: vec![LeadRef::Address(ADDR.into())],
        window: Some((ts(1_300_000_000), ts(1_310_000_000))),
        evidence: vec![disk],
    };
    case.replace_leads(&[lead("low", 10.0), lead("high", 90.0)]).unwrap();
    let stored = case.leads().unwrap();
    assert_eq!(stored.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(), ["high", "low"]);
    assert_eq!(stored[0], lead("high", 90.0));

    let ev = |kind, title: &str, artifact: &str| TimelineEvent::new(ts(1_310_000_000), kind, title, EventSource::new(artifact, "/p"));
    case.store_events(
        disk,
        &[
            ev(EventKind::UrlVisited, "https://mtgox.com/", "chrome.history").with_tag(CRYPTO_TAG),
            ev(EventKind::FileModified, "wallet.dat", "fs.ntfs").with_tag(CRYPTO_TAG),
            ev(EventKind::UrlVisited, "https://example.com/", "chrome.history"),
            ev(EventKind::AccountSeen, "user @ example.com", "chrome.login_data"),
        ],
    )
    .unwrap();
    let events = case.lead_events(100).unwrap();
    assert_eq!(events.iter().map(|e| e.event.title()).collect::<Vec<_>>(), ["https://mtgox.com/", "user @ example.com"]);
}
