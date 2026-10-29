//! People and what they did: accounts on services, mail between identities and from services,
//! messages naming addresses or keys, and the leads that tie things together.

use super::Draft;
use super::findings::{address, identity};
use super::ownership::Signals;
use crate::edge::{EdgeKind, Evidence};
use crate::facts::{Facts, MailFact};
use crate::node::{Node, NodeKey, NodeKind};
use crate::rank;
use std::collections::{BTreeMap, HashMap};
use strata_accounts::{Account, IdentifierKind, Service, ServiceKind};
use strata_leads::LeadRef;

/// Mail to more people than this is a newsletter or a list, not correspondence.
const MAX_RECIPIENTS: usize = 8;
/// Recipients of a message node linked to it.
const MESSAGE_RECIPIENTS: usize = 5;
/// Uncatalogued accounts below this confidence are left out.
const MIN_UNKNOWN_CONFIDENCE: f32 = 0.5;

/// The mailbox itself is no news: `olga@mail.ru` has an account on Mail.ru by definition.
fn worth_showing(a: &Account) -> bool {
    match a.service_kind() {
        Some(ServiceKind::Mail) => a.kind() != IdentifierKind::Email,
        Some(_) => true,
        None => a.confidence() >= MIN_UNKNOWN_CONFIDENCE,
    }
}

fn service_node(d: &mut Draft, key: &str, name: &str, kind: Option<ServiceKind>) -> usize {
    d.node(NodeKey::service(key), |k| Node::new(k, NodeKind::Service, name, kind.map_or("service", |k| k.label())))
}

pub(super) fn add_accounts(d: &mut Draft, facts: &Facts, signals: &Signals) {
    for a in facts.accounts.iter().filter(|a| worth_showing(a)) {
        let Some(person) = identity(d, signals, a.identifier(), a.kind()) else { continue };
        let account = d.node(NodeKey::account(a.key()), |k| {
            let what = a.service_kind().map_or("account".to_string(), |k| format!("{} account", k.label()));
            let mut n = Node::new(k, NodeKind::Account, format!("{} · {}", a.identifier(), a.service()), what);
            n.score = rank::account(a.service_kind(), a.confidence());
            if a.holds_funds() {
                n.because("the service holds funds: check for a balance or withdrawals");
            }
            n.because(format!("{} naming it", rank::plural(a.sources().len() as u64, "trace")));
            n
        });
        let node = d.at(account);
        node.seen(a.first_seen());
        node.seen(a.last_seen());
        a.disks().iter().for_each(|disk| node.on_disk(*disk));
        if let Some(hit) = a.sources().iter().find_map(|s| if let strata_accounts::SourceRef::Hit(h) = s.origin { Some(h) } else { None }) {
            node.hit.get_or_insert(hit);
        }
        for s in a.sources() {
            d.link(person, account, EdgeKind::HasAccount, Some(Evidence::trace(s)));
        }
        let service = service_node(d, a.service_id().unwrap_or(a.service()), a.service(), a.service_kind());
        d.link(account, service, EdgeKind::OnService, None);
    }
}

pub(super) fn add_mail(d: &mut Draft, facts: &Facts, signals: &Signals) {
    for m in &facts.mail {
        let evidence = || Some(Evidence::Message { id: m.id, at: m.at, subject: m.subject.clone() });
        let Some(sender) = m.from.first() else { continue };
        if let Some(service) = Service::classify_email(sender).filter(|s| s.kind.is_crypto() || s.kind.holds_funds()) {
            for to in &m.to {
                if let Some(person) = identity(d, signals, to, IdentifierKind::Email) {
                    let svc = service_node(d, service.id, service.name, Some(service.kind));
                    d.link(person, svc, EdgeKind::MailFromService, evidence());
                }
            }
            continue;
        }
        if m.to.len() > MAX_RECIPIENTS {
            continue;
        }
        let Some(from) = identity(d, signals, sender, IdentifierKind::Email) else { continue };
        d.at(from).seen(m.at);
        for to in &m.to {
            if let Some(to) = identity(d, signals, to, IdentifierKind::Email) {
                d.link(from, to, EdgeKind::Corresponded, evidence());
            }
        }
    }
    add_messages(d, facts, signals);
}

/// Messages whose body names an address, key or identity of the graph become nodes of their own.
fn add_messages(d: &mut Draft, facts: &Facts, signals: &Signals) {
    let by_id: HashMap<i64, &MailFact> = facts.mail.iter().map(|m| (m.id, m)).collect();
    let mut mentions: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
    for mention in &facts.mentions {
        let v = mention.value.as_str();
        let target = [NodeKey::address(v), NodeKey::secret(v), NodeKey::identity(v)].iter().find_map(|k| d.get(k));
        if let Some(t) = target {
            mentions.entry(mention.message).or_default().push(t);
        }
    }
    for (id, targets) in mentions {
        let Some(m) = by_id.get(&id) else { continue };
        let message = d.node(NodeKey::message(id), |k| {
            let subject = if m.subject.is_empty() { "(no subject)".to_string() } else { m.subject.clone() };
            let from = m.from.first().map(String::as_str).unwrap_or("unknown sender");
            let mut n = Node::new(k, NodeKind::Message, subject, format!("mail from {from}"));
            n.seen(m.at);
            n.on_disk(m.disk);
            n.score = 30.0;
            n
        });
        let evidence = || Some(Evidence::Message { id, at: m.at, subject: m.subject.clone() });
        for t in targets {
            if d.nodes[t].kind != NodeKind::Identity {
                d.at(message).score = 45.0;
            }
            d.link(message, t, EdgeKind::Mentions, evidence());
        }
        d.at(message).because("its text names an address, key or identity found on the disks");
        if let Some(from) = m.from.first().and_then(|f| identity(d, signals, f, IdentifierKind::Email)) {
            d.link(from, message, EdgeKind::Sent, evidence());
        }
        for to in m.to.iter().take(MESSAGE_RECIPIENTS) {
            if let Some(to) = identity(d, signals, to, IdentifierKind::Email) {
                d.link(message, to, EdgeKind::Received, evidence());
            }
        }
    }
}

pub(super) fn add_leads(d: &mut Draft, facts: &Facts) {
    let chain: HashMap<&str, &crate::facts::ChainFact> = facts.chain.iter().map(|c| (c.address.as_str(), c)).collect();
    for l in &facts.leads {
        let targets: Vec<usize> = l
            .refs
            .iter()
            .filter_map(|r| match r {
                LeadRef::Hit(id) => d.by_hit.get(id).copied(),
                LeadRef::Address(a) => Some(address(d, a, chain.get(a.as_str()).copied())),
                LeadRef::Account(key) => d.get(&NodeKey::account(key)),
                LeadRef::Event(_) => None,
            })
            .collect();
        if targets.is_empty() {
            continue;
        }
        let lead = d.node(NodeKey::lead(&l.id), |k| {
            let mut n = Node::new(k, NodeKind::Lead, l.title.clone(), l.rule.label());
            n.score = l.score * 0.85;
            n.why = l.explanation.clone();
            if let Some((from, to)) = l.window {
                n.seen(Some(from));
                n.seen(Some(to));
            }
            l.evidence.iter().for_each(|e| n.on_disk(*e));
            n
        });
        for t in targets {
            d.link(lead, t, EdgeKind::Refers, Some(Evidence::Lead { id: l.id.clone(), title: l.title.clone() }));
        }
    }
}
