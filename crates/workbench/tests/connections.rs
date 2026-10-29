//! The connection map end to end on a synthetic case: findings, mail, chain data and accounts in
//! the store, a ranked graph out, cached until the case changes. All values are made up.

use std::sync::Arc;
use strata_case::{Attribution, FileRef, FoundMessage, MessageLocation, MessageState};
use strata_chain::{AddressBalance, AddressHistory, AddressTx};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, EvidenceId, Timestamp};
use strata_workbench::{EdgeKind, MailContainer, Message, NodeKey, NodeKind, ViewScope, Workbench};

const ADDR: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const WIF: &str = "5KsyntheticTestKeyNotRealXXXXXXXXXXXXXXXXXXXXXXXXXX";
const OWNER: &str = "olga.test1@example.ru";
const KEYS: &str = "Users/olga/Desktop/keys.txt";

fn in_file(path: &str) -> Attribution {
    Attribution { volume: Some(0), file: Some(FileRef { path: path.into(), state: EntryState::Allocated, file_offset: 0 }) }
}

fn hit(detector: &str, category: HitCategory, label: &str, value: &str, confidence: f32) -> Hit {
    Hit::new(detector, category, 4096, value.len()).label(label).value(value).confidence(Confidence::new(confidence))
}

fn message(id: u32, from: &str, to: &str, subject: &str, body: &str) -> FoundMessage {
    let raw = format!("Message-ID: <m{id}@example.com>\r\nDate: Tue, 14 Jun 2011 12:{id:02}:00 +0000\r\nFrom: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}\r\n");
    let location = MessageLocation { state: MessageState::Live, container: MailContainer::Eml, volume: Some(0), file_idx: None, path: Some(format!("Mail/{id}.eml")), offset: 0, len: raw.len() as u64 };
    FoundMessage { location, folder: "Inbox".into(), message: Message::parse(raw.as_bytes()).unwrap() }
}

fn case(dir: &std::path::Path) -> (Arc<Workbench>, EvidenceId, EvidenceId) {
    let image = |name: &str| {
        let path = dir.join(name);
        std::fs::write(&path, vec![0u8; 1 << 20]).unwrap();
        path.display().to_string()
    };
    let wb = Workbench::open_idle(&dir.join("t.strata")).unwrap();
    let (laptop, usb) = (wb.add_evidence(&image("laptop.img")).unwrap().id, wb.add_evidence(&image("usb.img")).unwrap().id);
    let case = wb.case();
    let key = hit("crypto.wif", HitCategory::PrivateKey, "WIF private key", WIF, 0.9).details(serde_json::json!({"addresses": {"p2pkh": ADDR}}));
    let login = hit("accounts.login", HitCategory::Identity, "login", "olga_btc", 0.8).details(serde_json::json!({"service": "Mt. Gox"}));
    case.store_hits(
        laptop,
        &[
            (key, in_file(KEYS)),
            (login, in_file(KEYS)),
            (hit("crypto.hex", HitCategory::PrivateKey, "raw hex key", "00ff00ff", 0.1), in_file(KEYS)),
            (hit("accounts.email", HitCategory::Identity, "e-mail", "maintainer@example.org", 0.5), in_file("var/lib/dpkg/status")),
        ],
    )
    .unwrap();
    case.store_hits(usb, &[(hit("crypto.address", HitCategory::Address, "Bitcoin address", ADDR, 0.8), Attribution::default())]).unwrap();
    case.store_balance(&AddressBalance { address: ADDR.into(), funded_sat: 5_000_000, spent_sat: 0, tx_count: 1, mempool_delta_sat: 0, source: "mock".into() })
        .unwrap();
    let tx = AddressTx { txid: "t1".into(), time: Timestamp::from_civil(2011, 6, 14, 12, 0, 0), received_sat: 5_000_000, sent_sat: 0 };
    case.store_history(&AddressHistory { address: ADDR.into(), txs: vec![tx], tx_count: 1, total_received_sat: 5_000_000, complete: true, source: "mock".into() })
        .unwrap();
    let mail = [
        message(1, "ivan.test2@example.ru", OWNER, "hello", "how are you"),
        message(2, "ivan.test2@example.ru", OWNER, "coins", &format!("I sent them to {ADDR} yesterday")),
        message(3, OWNER, "ivan.test2@example.ru", "re: coins", "thanks"),
        message(4, "ivan.test2@example.ru", OWNER, "again", "see you"),
    ];
    case.write(|w| w.messages(laptop, &mail)).unwrap();
    wb.rebuild_insights().unwrap();
    (wb, laptop, usb)
}

#[test]
fn builds_a_ranked_graph_of_the_case_and_caches_it() {
    let dir = tempfile::tempdir().unwrap();
    let (wb, laptop, usb) = case(dir.path());
    let graph = wb.connections().unwrap();
    assert!(Arc::ptr_eq(&graph, &wb.connections().unwrap()), "an unchanged case reuses the graph");

    let key = NodeKey::secret(WIF);
    let detail = wb.connection_detail(key.as_str()).unwrap().expect("the key is a node");
    let link = |kind: EdgeKind, other: &NodeKey| detail.links.iter().find(|l| l.kind == kind && l.other.key() == other);
    assert!(link(EdgeKind::CoOccurs, &NodeKey::identity("olga_btc")).is_some(), "the login beside the key");
    assert!(link(EdgeKind::Derives, &NodeKey::address(ADDR)).is_some());
    assert!(link(EdgeKind::FoundIn, &NodeKey::file(laptop, KEYS)).is_some());
    assert!(graph.node(&NodeKey::secret("00ff00ff")).is_none(), "below the noise floor");
    assert!(graph.node(&NodeKey::identity("maintainer@example.org")).is_none(), "only in a package list");

    let address = graph.node(&NodeKey::address(ADDR)).unwrap();
    assert!(address.flags().funded);
    assert_eq!(address.disks(), [usb], "found on the usb stick, derived from a key on the laptop");
    let from_key = wb.connections_around(key.as_str(), &ViewScope::new(2, 50)).unwrap().unwrap();
    assert!(from_key.index_of(&NodeKey::disk(usb)).is_some(), "the key leads to the other disk");
    let owner = graph.node(&NodeKey::identity(OWNER)).unwrap();
    assert!(owner.flags().owner, "the live mailbox's recipient");
    let mention = wb.connection_detail(&NodeKey::address(ADDR).to_string()).unwrap().unwrap();
    assert!(mention.links.iter().any(|l| l.kind == EdgeKind::Mentions && l.other.kind() == NodeKind::Message));
    let account = graph.nodes().iter().find(|n| n.kind() == NodeKind::Account).expect("the Mt. Gox account");
    assert!(account.label().contains("olga_btc"));

    let around = wb.connections_default(&ViewScope::new(2, 10)).unwrap().unwrap();
    assert_eq!(around.nodes[0].node.key(), &NodeKey::identity(OWNER));
    assert!(around.nodes.len() <= 10);
    let overview = wb.connections_overview(&ViewScope::new(2, 12)).unwrap();
    assert!(overview.nodes.iter().any(|n| n.node.key() == &NodeKey::address(ADDR)));
    assert_eq!(wb.connections_around("OLGA_BTC", &ViewScope::default()).unwrap().unwrap().nodes[0].node.key(), &NodeKey::identity("olga_btc"));
    let stored = wb.hits(&strata_case::HitQuery { exact_value: Some(WIF.into()), ..Default::default() }).unwrap();
    assert_eq!(wb.connection_of_finding(stored[0].id, WIF).unwrap(), Some(key));

    wb.case().store_hits(usb, &[(hit("accounts.email", HitCategory::Identity, "e-mail", "new.test3@example.ru", 0.8), in_file("Users/olga/a.txt"))]).unwrap();
    assert!(!Arc::ptr_eq(&graph, &wb.connections().unwrap()), "new findings rebuild the graph");
}
