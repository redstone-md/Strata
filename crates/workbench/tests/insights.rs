//! End to end on a synthetic case: findings, events and a cached chain history in, accounts
//! and leads out.

use strata_case::{Attribution, FileRef};
use strata_chain::{AddressBalance, AddressHistory, AddressTx};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Timestamp};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};
use strata_workbench::{AccountQuery, LeadRule, ServiceGroup, ServiceKind, Standing, Workbench};

const ADDR: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

#[test]
fn rebuild_resolves_accounts_and_ranks_leads() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("zero.img");
    std::fs::write(&img, vec![0u8; 1 << 20]).unwrap();
    let wb = Workbench::open(&dir.path().join("t.strata")).unwrap();
    let disk = wb.add_evidence(&img.display().to_string()).unwrap().id;
    let case = wb.case();

    let wallet = "Documents and Settings/a/Application Data/Bitcoin/wallet.dat";
    let key = Hit::new("crypto.wif", HitCategory::PrivateKey, 4096, 52)
        .label("WIF private key")
        .value("synthetic-wif")
        .confidence(Confidence::HIGH)
        .details(serde_json::json!({"addresses": {"p2pkh": ADDR}}));
    let login = Hit::new("accounts.login", HitCategory::Identity, 8192, 30)
        .label("login (url)")
        .value("gox_tester")
        .confidence(Confidence::HIGH)
        .details(serde_json::json!({"service": "Mt. Gox", "service_id": "mtgox"}));
    let file = FileRef { path: wallet.into(), state: EntryState::Deleted, file_offset: 0 };
    let sighting = Hit::new("accounts.email", HitCategory::Identity, 9000, 20).label("e-mail").value("stranger@example.org");
    case.store_hits(disk, &[(key, Attribution { volume: Some(0), file: Some(file) }), (login, Attribution::default()), (sighting, Attribution::default())])
        .unwrap();

    let ev = |t, kind, title: &str| TimelineEvent::new(t, kind, title, EventSource::new("chrome.history", "/History")).with_tag(CRYPTO_TAG);
    case.store_events(
        disk,
        &[
            ev(at(2011, 6, 14), EventKind::UrlVisited, "http://freebitcoins.appspot.com/"),
            ev(at(2011, 11, 2), EventKind::AccountSeen, "gox_tester @ mtgox.com"),
            ev(at(2012, 2, 1), EventKind::UrlVisited, "https://mtgox.com/trade"),
        ],
    )
    .unwrap();
    case.store_balance(&AddressBalance { address: ADDR.into(), funded_sat: 5_000_000, spent_sat: 0, tx_count: 1, mempool_delta_sat: 0, source: "mock".into() })
        .unwrap();
    let tx = AddressTx { txid: "t1".into(), time: Some(at(2011, 6, 14)), received_sat: 5_000_000, sent_sat: 0 };
    case.store_history(&AddressHistory { address: ADDR.into(), txs: vec![tx], tx_count: 1, total_received_sat: 5_000_000, complete: true, source: "mock".into() })
        .unwrap();

    let (accounts, leads) = wb.rebuild_insights().unwrap();
    assert!(accounts >= 1 && leads >= 2, "{accounts} accounts, {leads} leads");

    let accounts = wb.accounts().unwrap();
    let gox = accounts.iter().find(|a| a.service_id() == Some("mtgox")).expect("Mt. Gox account");
    assert_eq!(gox.service_kind(), Some(ServiceKind::Exchange));
    assert_eq!(gox.first_seen(), Some(at(2011, 11, 2)), "dated by the account event");
    assert_eq!(gox.standing(), Standing::Used, "the account event shows use");
    assert!(accounts.iter().all(|a| a.identifier() != "stranger@example.org"), "plain sightings never become accounts");

    let used = wb.account_rows(&AccountQuery::default()).unwrap();
    assert!(used.iter().any(|r| r.identifier == "gox_tester" && r.group == ServiceGroup::Crypto));
    let seen = wb.account_rows(&AccountQuery { seen: true, ..Default::default() }).unwrap();
    assert!(seen.iter().any(|r| r.mention_only && r.identifier == "stranger@example.org"));
    let mention = wb.mention("Stranger@example.org").unwrap().unwrap();
    assert_eq!(wb.mention_hits(&mention, 10).unwrap().len(), 1);

    let leads = wb.leads().unwrap();
    assert_eq!(leads[0].rule, LeadRule::OnChainActivity, "{:?}", leads.iter().map(|l| &l.title).collect::<Vec<_>>());
    assert!(leads[0].text().contains("The Bitcoin Faucet"));
    assert!(leads.iter().any(|l| l.rule == LeadRule::AccountCheck && l.title.contains("gox_tester")));
}
