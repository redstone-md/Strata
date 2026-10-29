//! Findings become secrets, addresses and identities placed in files and on disks. A file with
//! a key, seed or wallet links it to everything found beside it; chain data adds coins and
//! shared transactions.

use super::Draft;
use super::ownership::Signals;
use crate::edge::{EdgeKind, Evidence};
use crate::facts::{ChainFact, Facts, FindingFact};
use crate::node::{ChainState, Node, NodeKey, NodeKind};
use crate::{paths, rank};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use strata_accounts::IdentifierKind;
use strata_kernel::EvidenceId;
use strata_kernel::scan::HitCategory;

/// Findings beside a secret linked to it per file (the rest stay reachable through the file).
const MAX_COOCCURRING: usize = 24;
/// Derived addresses not looked up on chain yet that still get a node, per secret.
const UNCHECKED_DERIVED: usize = 2;
/// Larger transactions (batched payouts, exchanges) say nothing about common ownership.
const MAX_TX_ADDRESSES: usize = 8;

pub(super) fn add(d: &mut Draft, facts: &Facts, signals: &Signals) {
    let chain: HashMap<&str, &ChainFact> = facts.chain.iter().map(|c| (c.address.as_str(), c)).collect();
    let wallets = wallet_files(d, facts);
    let mut files: BTreeMap<(EvidenceId, &str), Vec<(usize, bool, i64)>> = BTreeMap::new();
    let mut live: BTreeSet<usize> = BTreeSet::new();
    let mut touched: BTreeSet<usize> = BTreeSet::new();
    for f in &facts.findings {
        let Some(n) = finding_node(d, f, &chain, signals) else { continue };
        d.remember_hit(f.hit, n);
        let node = d.at(n);
        node.on_disk(f.disk);
        node.hit.get_or_insert(f.hit);
        touched.insert(n);
        if !f.deleted {
            live.insert(n);
        }
        let evidence = Evidence::Finding { hit: f.hit, disk: f.disk, file: f.file.clone() };
        match f.file.as_deref() {
            // Whatever is inside a wallet file hangs off the wallet itself.
            Some(path) if f.category != HitCategory::Wallet => match wallets.get(&(f.disk, path)) {
                Some(wallet) => d.link(n, *wallet, EdgeKind::FoundIn, Some(evidence)),
                None => {
                    let file = file_node(d, f, path);
                    d.link(n, file, EdgeKind::FoundIn, Some(evidence));
                    files.entry((f.disk, path)).or_default().push((n, f.is_secret(), f.hit));
                }
            },
            _ => {
                let disk = disk_node(d, f.disk);
                d.link(n, disk, EdgeKind::OnDisk, Some(evidence));
            }
        }
        if f.is_secret() {
            derive(d, n, f, &chain);
        }
    }
    for n in touched {
        d.at(n).flags.deleted = !live.contains(&n);
    }
    co_occurrence(d, files);
    transactions(d, facts);
}

fn btc(sat: u64) -> String {
    format!("{}.{:08} BTC", sat / 100_000_000, sat % 100_000_000)
}

/// An address node with its chain state, score and the reason for it.
pub(super) fn address(d: &mut Draft, value: &str, chain: Option<&ChainFact>) -> usize {
    d.node(NodeKey::address(value), |k| {
        let state = chain.map(|c| ChainState { funded_sat: c.funded_sat, spent_sat: c.spent_sat, tx_count: c.tx_count });
        let mut n = Node::new(k, NodeKind::Address, value, "address");
        n.chain = state;
        n.score = rank::address(state);
        match state {
            Some(s) if s.balance_sat() > 0 => {
                n.flags.funded = true;
                n.flags.used = true;
                n.caption = "address with a balance".into();
                n.because(format!("holds {} on chain", btc(s.balance_sat())));
            }
            Some(s) if s.used() => {
                n.flags.used = true;
                n.caption = "used address".into();
                n.because(format!("received {} in {}", btc(s.funded_sat), rank::plural(s.tx_count, "transaction")));
            }
            Some(_) => n.because("never used on chain"),
            None => n.because("not looked up on chain yet"),
        }
        if let Some(c) = chain {
            n.seen(c.first_seen);
            n.seen(c.last_seen);
        }
        n
    })
}

/// An identity node, unless the identity is noise.
pub(super) fn identity(d: &mut Draft, signals: &Signals, value: &str, kind: IdentifierKind) -> Option<usize> {
    if signals.is_noise(value) || value.trim().len() < 2 {
        return None;
    }
    let kind = if value.contains('@') { IdentifierKind::Email } else { kind };
    Some(d.node(NodeKey::identity(value), |k| Node::new(k, NodeKind::Identity, value.trim().to_lowercase(), kind.label())))
}

pub(super) fn disk_node(d: &mut Draft, disk: EvidenceId) -> usize {
    d.node(NodeKey::disk(disk), |k| {
        let mut n = Node::new(k, NodeKind::Disk, format!("disk {}", disk.get()), "disk");
        n.on_disk(disk);
        n
    })
}

fn finding_node(d: &mut Draft, f: &FindingFact, chain: &HashMap<&str, &ChainFact>, signals: &Signals) -> Option<usize> {
    match f.category {
        HitCategory::Identity => identity(d, signals, &f.value, IdentifierKind::from_label(&f.label)),
        HitCategory::Address => Some(address(d, &f.value, chain.get(f.value.as_str()).copied())),
        _ if f.is_secret() => Some(secret(d, f)),
        _ => None,
    }
}

fn secret(d: &mut Draft, f: &FindingFact) -> usize {
    let key = match (f.category, f.file.as_deref()) {
        (HitCategory::Wallet, Some(path)) => NodeKey::wallet(f.disk, path),
        (HitCategory::Wallet, None) => NodeKey::wallet(f.disk, &format!("#{}", f.hit)),
        _ => NodeKey::secret(&f.value),
    };
    let i = d.node(key, |k| {
        let label = match (f.category, f.file.as_deref()) {
            (HitCategory::Wallet, Some(path)) => paths::file_name(path).to_string(),
            _ => f.value.clone(),
        };
        let mut n = Node::new(k, NodeKind::Secret, label, f.label.clone());
        n.because(match f.category {
            HitCategory::Wallet => format!("wallet file: {}", f.value),
            HitCategory::Mnemonic => "seed phrase: restores a whole wallet".to_string(),
            HitCategory::ExtendedKey => "extended key: a whole branch of a wallet".to_string(),
            _ => "private key: spends what its addresses hold".to_string(),
        });
        n
    });
    let node = d.at(i);
    node.score = node.score.max(rank::secret(f.category, f.confidence));
    node.seen(f.file_times.0);
    node.seen(f.file_times.1);
    i
}

fn file_node(d: &mut Draft, f: &FindingFact, path: &str) -> usize {
    let key = NodeKey::file(f.disk, path);
    if let Some(i) = d.get(&key) {
        return i;
    }
    let disk = disk_node(d, f.disk);
    let i = d.node(key, |k| {
        let mut n = Node::new(k, NodeKind::File, paths::file_name(path), path);
        n.on_disk(f.disk);
        n.seen(f.file_times.0);
        n.seen(f.file_times.1);
        n.flags.deleted = f.deleted;
        n.score = 8.0;
        n
    });
    d.link(i, disk, EdgeKind::OnDisk, None);
    i
}

/// Addresses a key, seed or wallet controls: those used on chain, and a few not looked up yet.
fn derive(d: &mut Draft, secret: usize, f: &FindingFact, chain: &HashMap<&str, &ChainFact>) {
    let mut unchecked = 0;
    for a in &f.addresses {
        let c = chain.get(a.as_str()).copied();
        let keep = match c {
            Some(c) => c.tx_count > 0 || c.funded_sat > 0,
            None => {
                unchecked += 1;
                unchecked <= UNCHECKED_DERIVED
            }
        };
        if keep {
            let addr = address(d, a, c);
            d.link(secret, addr, EdgeKind::Derives, Some(Evidence::Finding { hit: f.hit, disk: f.disk, file: f.file.clone() }));
        }
    }
}

/// Secrets link to what shares their file; the file ranks with the best secret in it.
fn co_occurrence(d: &mut Draft, files: BTreeMap<(EvidenceId, &str), Vec<(usize, bool, i64)>>) {
    for ((disk, path), group) in files {
        let mut secrets: Vec<usize> = group.iter().filter(|g| g.1).map(|g| g.0).collect();
        secrets.sort_unstable();
        secrets.dedup();
        if secrets.is_empty() {
            continue;
        }
        let best = secrets.iter().map(|s| d.nodes[*s].score).fold(0.0f32, f32::max);
        if let Some(file) = d.get(&NodeKey::file(disk, path)) {
            let node = d.at(file);
            node.score = node.score.max(best * 0.55);
            node.because("holds a key, seed or wallet");
        }
        let mut seen = BTreeSet::new();
        let others: Vec<(usize, i64)> =
            group.iter().filter(|g| !secrets.contains(&g.0) && seen.insert(g.0)).take(MAX_COOCCURRING).map(|g| (g.0, g.2)).collect();
        for s in &secrets {
            for (o, hit) in &others {
                d.link(*s, *o, EdgeKind::CoOccurs, Some(Evidence::Finding { hit: *hit, disk, file: Some(path.to_string()) }));
            }
        }
    }
}

/// Addresses of the graph that appear together in a transaction.
fn transactions(d: &mut Draft, facts: &Facts) {
    let mut by_tx: BTreeMap<&str, (Option<strata_kernel::Timestamp>, Vec<usize>)> = BTreeMap::new();
    for c in &facts.chain {
        let Some(n) = d.get(&NodeKey::address(&c.address)) else { continue };
        for tx in &c.txs {
            let entry = by_tx.entry(tx.txid.as_str()).or_insert((tx.at, Vec::new()));
            if !entry.1.contains(&n) {
                entry.1.push(n);
            }
        }
    }
    for (txid, (at, nodes)) in by_tx {
        if nodes.len() < 2 || nodes.len() > MAX_TX_ADDRESSES {
            continue;
        }
        for (i, a) in nodes.iter().enumerate() {
            for b in &nodes[i + 1..] {
                d.link(*a, *b, EdgeKind::SameTransaction, Some(Evidence::Transaction { txid: txid.to_string(), at }));
            }
        }
    }
}

/// Files that are wallets: findings inside them hang off the wallet node itself.
fn wallet_files<'f>(d: &mut Draft, facts: &'f Facts) -> HashMap<(EvidenceId, &'f str), usize> {
    facts
        .findings
        .iter()
        .filter(|f| f.category == HitCategory::Wallet)
        .filter_map(|f| Some(((f.disk, f.file.as_deref()?), secret(d, f))))
        .collect()
}
