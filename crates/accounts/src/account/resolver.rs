use super::{Account, AccountSource, IdentifierKind, Observation};
use crate::service::Service;
use crate::url_accounts::looks_like_email;
use std::collections::{HashMap, HashSet};
use strata_kernel::Timestamp;

/// Evidence kept per account; more traces only raise confidence and widen the dates.
const MAX_SOURCES: usize = 64;
/// Linked accounts kept per account.
const MAX_LINKS: usize = 24;
/// Shortest e-mail local part used to link an address to a login of the same name.
const MIN_LINK_LEN: usize = 4;

/// Merges raw identity traces into [`Account`]s: one per (service, case-folded identifier),
/// across artefacts, byte hits and disks.
#[derive(Default)]
pub struct AccountResolver {
    accounts: Vec<Account>,
    index: HashMap<String, usize>,
    /// Case-folded identifier → accounts; rebuilt lazily after new observations.
    by_identifier: Option<HashMap<String, Vec<usize>>>,
}

struct ResolvedService {
    key: String,
    name: String,
    id: Option<String>,
    kind: Option<crate::ServiceKind>,
}

impl ResolvedService {
    fn of(service: Service) -> Self {
        Self { key: service.id.to_string(), name: service.name.to_string(), id: Some(service.id.to_string()), kind: Some(service.kind) }
    }

    /// Catalogue lookup of the trace's label; an uncatalogued label stays as given; an e-mail
    /// without any service belongs to its mail provider.
    fn resolve(label: Option<&str>, identifier: &str, kind: IdentifierKind) -> Self {
        let label = label.map(str::trim).filter(|l| !l.is_empty());
        if let Some(s) = label.and_then(Service::lookup) {
            return Self::of(s);
        }
        if let Some(l) = label {
            return Self { key: l.to_lowercase(), name: l.to_string(), id: None, kind: None };
        }
        if kind == IdentifierKind::Email
            && let Some(s) = Service::classify_email(identifier)
        {
            return Self::of(s);
        }
        let name = if kind == IdentifierKind::Email { identifier.rsplit_once('@').map_or("e-mail", |(_, d)| d) } else { "unknown service" };
        Self { key: name.to_lowercase(), name: name.to_string(), id: None, kind: None }
    }
}

fn min_ts(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

impl AccountResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one trace. Blank identifiers are ignored. An e-mail used as a login elsewhere also
    /// counts as a trace of the mailbox itself.
    pub fn observe(&mut self, obs: Observation) {
        let identifier = obs.identifier.trim().trim_matches(['"', '\'', '<', '>']).to_string();
        if identifier.len() < 2 {
            return;
        }
        let kind = if looks_like_email(&identifier) { IdentifierKind::Email } else { obs.kind };
        let service = ResolvedService::resolve(obs.service.as_deref(), &identifier, kind);
        if kind == IdentifierKind::Email
            && let Some(mailbox) = Service::classify_email(&identifier).filter(|m| Some(m.id) != service.id.as_deref())
        {
            let mut derived = obs.clone();
            derived.source.detail = format!("address used on {}", service.name);
            derived.confidence *= 0.8;
            self.merge(ResolvedService::of(mailbox), &identifier, kind, derived);
        }
        self.merge(service, &identifier, kind, obs);
    }

    fn merge(&mut self, service: ResolvedService, identifier: &str, kind: IdentifierKind, obs: Observation) {
        let folded = identifier.to_lowercase();
        let key = format!("{}|{folded}", service.key);
        self.by_identifier = None;
        let at_first = min_ts(obs.first_seen, obs.source.at);
        let at_last = obs.last_seen.max(obs.source.at);
        let i = *self.index.entry(key.clone()).or_insert_with(|| {
            self.accounts.push(Account {
                key,
                service: service.name,
                service_id: service.id,
                service_kind: service.kind,
                identifier: if kind == IdentifierKind::Email { folded.clone() } else { identifier.to_string() },
                kind,
                sources: Vec::new(),
                disks: Vec::new(),
                first_seen: None,
                last_seen: None,
                confidence: 0.0,
                linked: Vec::new(),
            });
            self.accounts.len() - 1
        });
        let a = &mut self.accounts[i];
        if kind.strength() > a.kind.strength() {
            a.kind = kind;
        }
        a.first_seen = min_ts(a.first_seen, at_first);
        a.last_seen = a.last_seen.max(at_last);
        if !a.disks.contains(&obs.source.evidence) {
            a.disks.push(obs.source.evidence);
            a.disks.sort();
        }
        if a.sources.len() < MAX_SOURCES && !a.sources.iter().any(|s| s.evidence == obs.source.evidence && s.origin == obs.source.origin) {
            a.sources.push(obs.source);
        }
        // Independent traces raise confidence (noisy-or), never to certainty.
        a.confidence = (1.0 - (1.0 - a.confidence) * (1.0 - obs.confidence.clamp(0.0, 1.0))).min(0.99);
    }

    /// Date accounts by events that mention their identifier: `tokens` are case-folded words of
    /// one event (title, detail). Only existing accounts are touched.
    pub fn date_mention(&mut self, tokens: &[String], source: AccountSource) {
        let Some(at) = source.at else { return };
        let accounts = &self.accounts;
        let map = self.by_identifier.get_or_insert_with(|| {
            let mut m: HashMap<String, Vec<usize>> = HashMap::new();
            for (i, a) in accounts.iter().enumerate() {
                m.entry(a.identifier.to_lowercase()).or_default().push(i);
            }
            m
        });
        let mut hits: Vec<usize> = tokens.iter().filter(|t| t.len() >= 3).filter_map(|t| map.get(t.as_str())).flatten().copied().collect();
        hits.sort_unstable();
        hits.dedup();
        for i in hits {
            let a = &mut self.accounts[i];
            a.first_seen = min_ts(a.first_seen, Some(at));
            a.last_seen = a.last_seen.max(Some(at));
            if a.sources.len() < MAX_SOURCES && !a.sources.iter().any(|s| s.origin == source.origin) {
                a.sources.push(source.clone());
            }
            if !a.disks.contains(&source.evidence) {
                a.disks.push(source.evidence);
                a.disks.sort();
            }
        }
    }

    /// Link accounts sharing an identifier (or an e-mail local part equal to a login), then
    /// return them: fund-holding services first, then by service and identifier.
    pub fn finish(mut self) -> Vec<Account> {
        let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, a) in self.accounts.iter().enumerate() {
            let mut keys: HashSet<String> = HashSet::from([a.identifier.to_lowercase()]);
            if let Some((local, _)) = a.identifier.split_once('@').filter(|(l, _)| l.len() >= MIN_LINK_LEN) {
                keys.insert(local.to_lowercase());
            }
            for k in keys {
                groups.entry(k).or_default().push(i);
            }
        }
        for members in groups.values().filter(|m| m.len() > 1) {
            for &i in members {
                for &j in members.iter().filter(|&&j| j != i) {
                    let other = self.accounts[j].key.clone();
                    let a = &mut self.accounts[i];
                    if a.linked.len() < MAX_LINKS && !a.linked.contains(&other) {
                        a.linked.push(other);
                    }
                }
            }
        }
        self.accounts.sort_by(|a, b| {
            (!a.holds_funds(), a.service_kind, a.service.to_lowercase(), a.identifier.to_lowercase())
                .cmp(&(!b.holds_funds(), b.service_kind, b.service.to_lowercase(), b.identifier.to_lowercase()))
        });
        self.accounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::SourceRef;
    use strata_kernel::EvidenceId;

    fn ts(s: i64) -> Option<Timestamp> {
        Timestamp::from_unix_secs(s)
    }

    fn obs(service: Option<&str>, id: &str, kind: IdentifierKind, disk: u32, hit: i64, at: i64) -> Observation {
        Observation {
            service: service.map(str::to_string),
            identifier: id.to_string(),
            kind,
            source: AccountSource { evidence: EvidenceId::new(disk), origin: SourceRef::Hit(hit), detail: "test".into(), at: ts(at) },
            first_seen: None,
            last_seen: None,
            confidence: 0.5,
        }
    }

    #[test]
    fn merges_case_folded_across_disks_and_labels() {
        let mut r = AccountResolver::new();
        r.observe(obs(Some("mtgox.com"), "Satoshi_Fan", IdentifierKind::Login, 1, 1, 1_300_000_000));
        r.observe(obs(Some("Mt. Gox"), "satoshi_fan", IdentifierKind::Nickname, 2, 7, 1_320_000_000));
        r.observe(obs(None, "Ivan.Test2@Mail.ru", IdentifierKind::Email, 1, 3, 1_310_000_000));
        let accounts = r.finish();
        let gox = accounts.iter().find(|a| a.service_id() == Some("mtgox")).unwrap();
        assert_eq!(gox.identifier(), "Satoshi_Fan");
        assert_eq!(gox.kind(), IdentifierKind::Login);
        assert_eq!(gox.disks(), [EvidenceId::new(1), EvidenceId::new(2)]);
        assert_eq!(gox.sources().len(), 2);
        assert_eq!(gox.window(), Some((ts(1_300_000_000).unwrap(), ts(1_320_000_000).unwrap())));
        assert!((gox.confidence() - 0.75).abs() < 1e-6);
        let mail = accounts.iter().find(|a| a.service_id() == Some("mailru")).unwrap();
        assert_eq!(mail.identifier(), "ivan.test2@mail.ru");
        assert_eq!(accounts[0].service_id(), Some("mtgox"), "fund-holding services sort first");
    }

    #[test]
    fn email_login_also_counts_for_mailbox_and_links() {
        let mut r = AccountResolver::new();
        r.observe(obs(Some("btc-e.com"), "olga.test1@yandex.ru", IdentifierKind::Login, 1, 1, 1_350_000_000));
        r.observe(obs(Some("bitcointalk.org"), "olga.test1", IdentifierKind::Nickname, 1, 2, 1_340_000_000));
        let accounts = r.finish();
        assert_eq!(accounts.len(), 3);
        let btce = accounts.iter().find(|a| a.service_id() == Some("btce")).unwrap();
        assert_eq!(btce.kind(), IdentifierKind::Email);
        assert!(accounts.iter().any(|a| a.service_id() == Some("yandex")));
        let talk = accounts.iter().find(|a| a.service_id() == Some("bitcointalk")).unwrap();
        assert_eq!(talk.linked().len(), 2, "linked to the e-mail on BTC-e and to the mailbox");
    }

    #[test]
    fn mentions_widen_dates_of_known_accounts_only() {
        let mut r = AccountResolver::new();
        r.observe(obs(Some("Windows"), "Admin", IdentifierKind::Login, 1, 1, 1_300_000_000));
        let src = AccountSource { evidence: EvidenceId::new(1), origin: SourceRef::Event(9), detail: "logon".into(), at: ts(1_400_000_000) };
        r.date_mention(&["admin".into(), "unrelated".into()], src);
        let accounts = r.finish();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].service(), "Windows");
        assert_eq!(accounts[0].last_seen(), ts(1_400_000_000));
        assert_eq!(accounts[0].sources().len(), 2);
    }
}
