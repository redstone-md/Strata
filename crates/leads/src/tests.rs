//! The engine on a synthetic case: one disk, a deleted wallet.dat whose address took coins
//! from a faucet, a seed written after an Electrum download, a Mt. Gox account, and a burst of
//! faucet use with nothing else from that time.

use crate::{EventRecord, KeyFinding, LeadEngine, LeadInputs, LeadRule};
use strata_accounts::{AccountResolver, AccountSource, IdentifierKind, Observation, SourceRef};
use strata_chain::{AddressHistory, AddressTx};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_timeline::{CRYPTO_TAG, EventKind, EventSource, TimelineEvent};

const A1: &str = "1SyntheticAddrOneXXXXXXXXXXXXXXXXX";
const A2: &str = "1SyntheticAddrTwoXXXXXXXXXXXXXXXXX";

fn at(y: i64, m: i64, d: i64, h: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, h, 0, 0).unwrap()
}

fn disk() -> EvidenceId {
    EvidenceId::new(1)
}

fn event(id: i64, t: Timestamp, kind: EventKind, title: &str) -> EventRecord {
    let e = TimelineEvent::new(t, kind, title, EventSource::new("test", "/synthetic")).with_tag(CRYPTO_TAG);
    EventRecord { id, evidence: disk(), event: e }
}

fn key(hit_id: i64, category: HitCategory, path: Option<&str>, deleted: bool, created: Option<Timestamp>, modified: Option<Timestamp>, addresses: &[&str]) -> KeyFinding {
    KeyFinding {
        hit_id,
        evidence: disk(),
        category,
        label: "synthetic".into(),
        value: format!("value-{hit_id}"),
        file_path: path.map(str::to_string),
        deleted,
        file_created: created,
        file_modified: modified,
        addresses: addresses.iter().map(|a| a.to_string()).collect(),
    }
}

fn history(address: &str, txs: &[(Timestamp, u64, u64)]) -> AddressHistory {
    AddressHistory {
        address: address.into(),
        txs: txs.iter().enumerate().map(|(i, (t, r, s))| AddressTx { txid: format!("{address}-{i}"), time: Some(*t), received_sat: *r, sent_sat: *s }).collect(),
        tx_count: txs.len() as u64,
        total_received_sat: txs.iter().map(|t| t.1).sum(),
        complete: true,
        source: "mock".into(),
    }
}

fn inputs() -> LeadInputs {
    let mut events = vec![
        event(1, at(2011, 6, 14, 10), EventKind::UrlVisited, "http://freebitcoins.appspot.com/"),
        event(2, at(2011, 6, 14, 11), EventKind::ProgramRun, "C:\\Program Files\\Bitcoin\\bitcoin-qt.exe"),
        event(3, at(2014, 1, 9, 20), EventKind::Download, "C:\\Users\\a\\Downloads\\electrum-1.9.7-setup.exe"),
    ];
    for (i, (m, d)) in [(11, 1), (12, 10), (1, 20), (3, 1), (4, 1)].into_iter().enumerate() {
        let y = if m >= 11 { 2011 } else { 2012 };
        events.push(event(10 + i as i64, at(y, m, d, 12), EventKind::UrlVisited, "https://mtgox.com/trade"));
    }
    for d in 0..6 {
        events.push(event(20 + d, at(2015, 3, 1 + d * 3, 9), EventKind::UrlVisited, "https://freebitco.in/?op=home"));
    }
    let mut resolver = AccountResolver::new();
    for (hit, t) in [(30, at(2011, 11, 1, 12)), (31, at(2012, 4, 1, 12))] {
        resolver.observe(Observation {
            service: Some("mtgox.com".into()),
            identifier: "gox_tester".into(),
            kind: IdentifierKind::Login,
            source: AccountSource { evidence: disk(), origin: SourceRef::Hit(hit), detail: "saved browser login".into(), at: Some(t) },
            first_seen: None,
            last_seen: None,
            confidence: 0.5,
        });
    }
    LeadInputs {
        keys: vec![
            key(10, HitCategory::PrivateKey, Some("Documents and Settings/Admin/Application Data/Bitcoin/wallet.dat"), true, Some(at(2011, 5, 1, 9)), Some(at(2012, 3, 2, 18)), &[A1]),
            key(11, HitCategory::Mnemonic, Some("Users/a/Documents/seed.txt"), false, Some(at(2014, 1, 10, 8)), Some(at(2014, 1, 10, 8)), &[]),
            key(12, HitCategory::Address, None, false, None, None, &[A2]),
        ],
        histories: vec![
            history(A1, &[(at(2011, 6, 14, 12), 5_000_000, 0), (at(2012, 1, 5, 12), 0, 2_000_000)]),
            history(A2, &[(at(2016, 1, 1, 0), 1_000, 0)]),
        ],
        events,
        accounts: resolver.finish(),
    }
}

#[test]
fn synthetic_case_gives_the_expected_top_leads() {
    let leads = LeadEngine::new().run(&inputs());
    let ids: Vec<&str> = leads.iter().map(|l| l.id.as_str()).collect();
    assert!(leads.windows(2).all(|w| w[0].score >= w[1].score), "{ids:?}");
    assert_eq!(ids[0], format!("onchain:{A1}"), "{ids:?}");

    let top = &leads[0];
    let text = top.text();
    assert_eq!(top.title, "1Synth…XXXXXX received 0.05 BTC on 2011-06-14");
    assert!(text.contains("visited the faucet The Bitcoin Faucet"), "{text}");
    assert!(text.contains("ran Bitcoin Core"), "{text}");
    assert!(text.contains("still holds 0.03 BTC"), "{text}");
    assert!(text.contains("(deleted file)"), "{text}");
    assert!(top.hits().eq([10]) && top.addresses().eq([A1]) && top.events().count() == 2);

    let install = leads.iter().find(|l| l.id == "install:11").expect("seed after Electrum download");
    assert!(install.title.contains("Electrum") && install.title.contains("2014-01-10"), "{}", install.title);

    let wallet = leads.iter().find(|l| l.id == "wallet:10").expect("wallet.dat during Mt. Gox use");
    assert!(wallet.title.contains("Mt. Gox") && wallet.title.contains("gox_tester"), "{}", wallet.title);
    assert!(wallet.title.contains("2012-03-02"));

    let account = leads.iter().find(|l| l.rule == LeadRule::AccountCheck).expect("account to check");
    assert!(account.text().contains("Found addresses moved coins while it was in use"), "{}", account.text());
    assert!(account.text().contains("Mt. Gox operated 2010–2014"));

    let gap = leads.iter().find(|l| l.rule == LeadRule::ActivityWithoutWallet).expect("2015 faucet burst without wallet");
    assert!(gap.title.contains("2015-03-01 to 2015-03-16"), "{}", gap.title);
    assert!(gap.text().contains("6 faucet visits"));

    let lone = leads.iter().find(|l| l.id == format!("onchain:{A2}")).expect("address with no context still listed");
    assert!(lone.score < install.score);
    assert!(lone.text().contains("Only the address was found"), "{}", lone.text());
}

#[test]
fn same_inputs_same_leads_and_empty_inputs_no_leads() {
    let a = LeadEngine::new().run(&inputs());
    let b = LeadEngine::new().run(&inputs());
    assert_eq!(a, b);
    assert!(LeadEngine::new().run(&LeadInputs::default()).is_empty());
}
