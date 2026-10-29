//! The graph built from a small synthetic case: two disks, a key file with a login beside it,
//! a browser login, live mail, a service mail, an exchange account, chain data, a lead, and the
//! kind of noise real disks are full of. All values are made up.

use crate::*;
use strata_accounts::{AccountResolver, AccountSource, IdentifierKind, Observation, SourceRef};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::{Lead, LeadRef, LeadRule};

const KEY: &str = "5KsyntheticTestKeyNotRealXXXXXXXXXXXXXXXXXXXXXXXXXX";
const FUNDED: &str = "1SyntheticFundedAddrXXXXXXXXXXXXXX";
const SPENT: &str = "1SyntheticSpentAddrXXXXXXXXXXXXXXX";
const UNCHECKED: &str = "1SyntheticUncheckedAddrXXXXXXXXXXX";
const OWNER: &str = "olga.test@example.ru";
const FRIEND: &str = "ivan.test@example.ru";
const KEYS_TXT: &str = "Users/olga/Desktop/keys.txt";

fn disk(n: u32) -> EvidenceId {
    EvidenceId::new(n)
}

fn at(day: i64) -> Option<Timestamp> {
    Timestamp::from_unix_secs(1_300_000_000 + day * 86_400)
}

fn finding(hit: i64, d: u32, category: HitCategory, label: &str, value: &str, file: Option<&str>) -> FindingFact {
    FindingFact {
        hit,
        disk: disk(d),
        category,
        detector: "test".into(),
        label: label.into(),
        value: value.into(),
        confidence: 0.8,
        file: file.map(str::to_string),
        deleted: false,
        file_times: (at(1), at(2)),
        addresses: Vec::new(),
        detail: None,
    }
}

fn mail(id: i64, from: &str, to: &[&str], subject: &str) -> MailFact {
    MailFact { id, disk: disk(1), at: at(id), live: true, from: vec![from.into()], to: to.iter().map(|t| t.to_string()).collect(), subject: subject.into() }
}

fn account(service: &str, identifier: &str, hit: i64) -> Observation {
    Observation {
        service: Some(service.into()),
        identifier: identifier.into(),
        kind: IdentifierKind::Login,
        source: AccountSource { evidence: disk(1), origin: SourceRef::Hit(hit), detail: "saved browser login".into(), at: at(5), trace: strata_accounts::TraceKind::SavedPassword },
        first_seen: at(5),
        last_seen: at(9),
        confidence: 0.9,
    }
}

fn chain(address: &str, funded: u64, spent: u64) -> ChainFact {
    ChainFact { address: address.into(), funded_sat: funded, spent_sat: spent, tx_count: 1, first_seen: at(3), last_seen: at(3), txs: vec![TxFact { txid: "t1".into(), at: at(3) }] }
}

fn facts() -> Facts {
    let mut key = finding(1, 1, HitCategory::PrivateKey, "WIF private key", KEY, Some(KEYS_TXT));
    key.addresses = vec![FUNDED.into(), UNCHECKED.into()];
    let mut browser = finding(3, 1, HitCategory::Identity, "e-mail (artefact)", OWNER, Some("Users/olga/AppData/Local/Google/Chrome/User Data/Default/Login Data"));
    browser.detector = "artifacts.identity".into();
    browser.detail = Some("saved browser login".into());
    let mut resolver = AccountResolver::new();
    resolver.observe(account("Mt. Gox", "olga_btc", 2));
    let lead = Lead {
        id: "lead-1".into(),
        rule: LeadRule::OnChainActivity,
        title: "Key with coins".into(),
        explanation: vec!["The key's address received coins.".into()],
        score: 80.0,
        refs: vec![LeadRef::Hit(1), LeadRef::Address(FUNDED.into())],
        window: None,
        evidence: vec![disk(1)],
    };
    let spread = |value: &str, files: u64, paths: &[&str]| SpreadFact {
        value: value.into(),
        copies: files * 2,
        files,
        disks: vec![disk(1)],
        sample_paths: paths.iter().map(|p| p.to_string()).collect(),
    };
    Facts {
        disks: vec![DiskFact { id: disk(1), label: "laptop".into() }, DiskFact { id: disk(2), label: "usb".into() }],
        findings: vec![
            key,
            finding(2, 1, HitCategory::Identity, "login", "olga_btc", Some(KEYS_TXT)),
            finding(4, 1, HitCategory::Address, "Bitcoin address", FUNDED, Some(KEYS_TXT)),
            finding(5, 2, HitCategory::Address, "Bitcoin address", FUNDED, None),
            finding(6, 2, HitCategory::Address, "Bitcoin address", SPENT, None),
            browser,
            finding(8, 1, HitCategory::Identity, "e-mail", "maintainer@example.org", Some("var/lib/dpkg/status")),
            finding(9, 1, HitCategory::Identity, "e-mail", "list@example.com", Some("Users/olga/Downloads/dump.sql")),
        ],
        spreads: vec![
            spread("maintainer@example.org", 2, &["var/lib/dpkg/status", "usr/share/doc/x/copyright"]),
            spread("list@example.com", 4_000, &["Users/olga/Downloads/dump.sql"]),
        ],
        accounts: resolver.finish(),
        chain: vec![chain(FUNDED, 5_000_000, 0), chain(SPENT, 900, 900)],
        mail: vec![
            mail(10, FRIEND, &[OWNER], "hello"),
            mail(11, FRIEND, &[OWNER], "keys"),
            mail(12, OWNER, &[FRIEND], "re: keys"),
            mail(13, FRIEND, &[OWNER], "again"),
            mail(14, "noreply@mtgox.com", &[OWNER], "Your deposit address"),
        ],
        mentions: vec![MentionFact { message: 14, value: FUNDED.into() }],
        leads: vec![lead],
    }
}

fn edge<'g>(g: &'g Graph, a: &NodeKey, b: &NodeKey, kind: EdgeKind) -> Option<&'g Edge> {
    let (ia, ib) = (g.nodes().iter().position(|n| n.key() == a)?, g.nodes().iter().position(|n| n.key() == b)?);
    g.edges().iter().find(|e| e.kind() == kind && ((e.from() == ia && e.to() == ib) || (e.from() == ib && e.to() == ia)))
}

#[test]
fn links_findings_files_accounts_mail_and_chain() {
    let g = GraphBuilder::build(&facts());
    let (key, login, owner) = (NodeKey::secret(KEY), NodeKey::identity("olga_btc"), NodeKey::identity(OWNER));
    let co = edge(&g, &key, &login, EdgeKind::CoOccurs).expect("the login sits in the key's file");
    assert!(matches!(&co.evidence()[0], Evidence::Finding { hit: 2, file: Some(f), .. } if f == KEYS_TXT));
    assert!(edge(&g, &key, &NodeKey::address(FUNDED), EdgeKind::Derives).is_some());
    assert!(edge(&g, &key, &NodeKey::file(disk(1), KEYS_TXT), EdgeKind::FoundIn).is_some());
    assert!(g.node(&NodeKey::address(UNCHECKED)).is_some(), "a derived address not looked up yet is shown");

    let account = g.nodes().iter().find(|n| n.kind() == NodeKind::Account).expect("the Mt. Gox account");
    assert!(edge(&g, &login, account.key(), EdgeKind::HasAccount).is_some());
    assert!(edge(&g, account.key(), &NodeKey::service("mtgox"), EdgeKind::OnService).is_some());

    let talk = edge(&g, &owner, &NodeKey::identity(FRIEND), EdgeKind::Corresponded).expect("mail both ways");
    assert_eq!((talk.count(), talk.evidence().len()), (4, 4));
    assert!(edge(&g, &owner, &NodeKey::service("mtgox"), EdgeKind::MailFromService).is_some());
    assert!(edge(&g, &NodeKey::message(14), &NodeKey::address(FUNDED), EdgeKind::Mentions).is_some());
    assert!(edge(&g, &NodeKey::address(FUNDED), &NodeKey::address(SPENT), EdgeKind::SameTransaction).is_some());
    assert!(edge(&g, &NodeKey::lead("lead-1"), &key, EdgeKind::Refers).is_some());

    let funded = g.node(&NodeKey::address(FUNDED)).unwrap();
    assert!(funded.flags().funded && funded.flags().cross_disk);
    assert_eq!(funded.disks(), [disk(1), disk(2)]);
    assert!(edge(&g, &NodeKey::address(FUNDED), &NodeKey::disk(disk(2)), EdgeKind::OnDisk).is_some());
    assert_eq!(g.node_of_hit(5).map(|n| n.key().clone()), Some(NodeKey::address(FUNDED)));
}

#[test]
fn leaves_noise_out_and_finds_the_owner() {
    let g = GraphBuilder::build(&facts());
    assert!(g.node(&NodeKey::identity("maintainer@example.org")).is_none(), "only in system files");
    assert!(g.node(&NodeKey::identity("list@example.com")).is_none(), "in thousands of files, never used");
    let owner = g.node(&NodeKey::identity(OWNER)).unwrap();
    assert!(owner.flags().owner);
    assert!(owner.why().iter().any(|w| w.contains("saved browser login")));
    assert_eq!(g.default_centre().map(|n| n.key().clone()), Some(NodeKey::identity(OWNER)));
    let score = |k: &NodeKey| g.node(k).unwrap().score();
    assert!(score(&NodeKey::address(FUNDED)) > score(&NodeKey::secret(KEY)));
    assert!(score(&NodeKey::secret(KEY)) > score(&NodeKey::identity(FRIEND)));
    assert_eq!(g.resolve("OLGA.TEST@example.ru").map(|n| n.key().clone()), Some(NodeKey::identity(OWNER)));
    assert_eq!(g.resolve(&format!("addr:{FUNDED}")).map(|n| n.kind()), Some(NodeKind::Address));
    assert!(g.find("synthetic", 10).len() >= 3);
}

#[test]
fn ego_networks_respect_caps_and_hubs() {
    let g = GraphBuilder::build(&facts());
    let owner = NodeKey::identity(OWNER);
    let small = g.around(&owner, &ViewScope::new(2, 4)).unwrap();
    assert_eq!((small.nodes.len(), small.centre), (4, Some(0)));
    assert_eq!(small.nodes[0].node.key(), &owner);
    assert!(small.left_out > 0 && small.nodes.iter().any(|n| n.more > 0));
    assert!(small.edges.iter().all(|e| e.from < 4 && e.to < 4));
    // The usb disk is reachable from the key only through the funded address, never through
    // the laptop disk.
    let wide = g.around(&NodeKey::secret(KEY), &ViewScope::new(3, 400)).unwrap();
    let laptop = wide.index_of(&NodeKey::disk(disk(1))).unwrap();
    assert!(wide.neighbours(laptop).iter().all(|n| wide.nodes[*n].depth < wide.nodes[laptop].depth || wide.nodes[*n].depth <= 2));
    let only = g.around(&owner, &ViewScope::new(2, 50).kinds(vec![NodeKind::Identity])).unwrap();
    assert!(only.nodes.len() >= 2 && only.nodes.iter().all(|n| n.node.kind() == NodeKind::Identity));
    let all = g.overview(&ViewScope::new(2, 6));
    assert!(all.nodes.len() <= 6 && all.nodes.iter().any(|n| n.node.key() == &NodeKey::address(FUNDED)));
    let detail = g.detail(&NodeKey::secret(KEY)).unwrap();
    assert!(detail.links.iter().any(|l| l.kind == EdgeKind::Derives && l.outgoing && l.phrase() == "derives"));
    assert!(detail.links.iter().all(|l| !l.evidence.is_empty() || matches!(l.kind, EdgeKind::OnDisk | EdgeKind::OnService)));
}

#[test]
fn layout_is_deterministic_and_finite() {
    let g = GraphBuilder::build(&facts());
    let view = g.around(&NodeKey::identity(OWNER), &ViewScope::default()).unwrap();
    let (a, b) = (Layout::compute(&view), Layout::compute(&view));
    assert_eq!(a, b);
    assert_eq!(a.len(), view.nodes.len());
    assert_eq!(a.point(0), Some((0.0, 0.0)), "the centre stays put");
    for i in 0..a.len() {
        let (x, y) = a.point(i).unwrap();
        assert!(x.is_finite() && y.is_finite());
        for j in i + 1..a.len() {
            let (u, v) = a.point(j).unwrap();
            assert!((x - u).hypot(y - v) > 5.0, "nodes {i} and {j} overlap");
        }
    }
    let rebuilt = GraphBuilder::build(&facts());
    assert_eq!(Layout::compute(&rebuilt.around(&NodeKey::identity(OWNER), &ViewScope::default()).unwrap()), a, "same facts, same picture");
    assert!(Layout::compute(&GraphView::default()).is_empty());
}
