//! Turns stored identity findings, service URLs and account-related events into
//! [`Observation`]s for the [`AccountResolver`].

use strata_accounts::{Account, AccountResolver, AccountSource, IdentifierKind, Observation, SourceRef, UrlAccounts};
use strata_case::{HitQuery, StoredHit};
use strata_kernel::Timestamp;
use strata_kernel::scan::HitCategory;
use strata_leads::EventRecord;
use strata_timeline::EventKind;

/// Event kinds whose words may name an account (dates its use).
const DATING_KINDS: &[EventKind] = &[EventKind::AccountSeen, EventKind::Login, EventKind::FormInput, EventKind::Email, EventKind::Cookie];

pub(crate) struct AccountsBuilder;

impl AccountsBuilder {
    pub fn build(case: &strata_case::Case, events: &[EventRecord]) -> strata_kernel::Result<Vec<Account>> {
        let mut resolver = AccountResolver::new();
        let query = HitQuery { categories: vec![HitCategory::Identity, HitCategory::Url], ..HitQuery::default() };
        for hit in case.hits(&query)? {
            for obs in observations(&hit) {
                resolver.observe(obs);
            }
        }
        for e in events.iter().filter(|e| DATING_KINDS.contains(&e.event.kind())) {
            let source = AccountSource {
                evidence: e.evidence,
                origin: SourceRef::Event(e.id),
                detail: format!("{} event", kind_word(e.event.kind())),
                at: Some(e.event.at()),
            };
            resolver.date_mention(&tokens(&format!("{} {}", e.event.title(), e.event.detail())), source);
        }
        Ok(resolver.finish())
    }
}

fn kind_word(kind: EventKind) -> &'static str {
    match kind {
        EventKind::AccountSeen => "account",
        EventKind::Login => "login",
        EventKind::FormInput => "form input",
        EventKind::Email => "mail",
        _ => "cookie",
    }
}

/// Case-folded words that could be identifiers (`user`, `user@mail.ru`, `login=user` → `user`).
fn tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .split(|c: char| c.is_whitespace() || "=,;:<>\"'()[]{}/?&|".contains(c))
        .map(|t| t.trim_matches(['.', '-']).to_lowercase())
        .filter(|t| t.len() >= 3 && t.len() <= 64)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn str_field<'a>(details: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    details.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

fn ts_field(details: &serde_json::Value, key: &str) -> Option<Timestamp> {
    details.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Observations carried by one stored finding.
fn observations(hit: &StoredHit) -> Vec<Observation> {
    let h = &hit.hit;
    let place = hit.file_path.as_deref().map(|p| format!(" in {p}")).unwrap_or_default();
    let source = |detail: String, at: Option<Timestamp>| AccountSource { evidence: hit.evidence, origin: SourceRef::Hit(hit.id), detail, at };
    match h.category {
        HitCategory::Url => UrlAccounts::extract(&h.value)
            .into_iter()
            .map(|a| Observation {
                service: a.service.map(|s| s.name.to_string()),
                identifier: a.value,
                kind: a.kind,
                source: source(format!("URL field {}{place}", a.field), None),
                first_seen: None,
                last_seen: None,
                confidence: h.confidence.get() * 0.8,
            })
            .collect(),
        HitCategory::Identity if h.detector == "artifacts.identity" => {
            let d = &h.details;
            let note = str_field(d, "detail").map(str::to_string).unwrap_or_else(|| format!("{}{place}", h.label));
            let weak = d.get("weak").and_then(|v| v.as_bool()).unwrap_or(false);
            vec![Observation {
                service: str_field(d, "service").map(str::to_string),
                identifier: str_field(d, "value").unwrap_or(&h.value).to_string(),
                kind: IdentifierKind::from_label(str_field(d, "kind").unwrap_or(&h.label)),
                source: source(note, None),
                first_seen: ts_field(d, "first_seen"),
                last_seen: ts_field(d, "last_seen"),
                confidence: if weak { 0.4 } else { h.confidence.get() },
            }]
        }
        HitCategory::Identity => vec![Observation {
            service: str_field(&h.details, "service").map(str::to_string),
            identifier: h.value.clone(),
            kind: IdentifierKind::from_label(&h.label),
            source: source(format!("{} on the disk{place}", h.label), None),
            first_seen: None,
            last_seen: None,
            confidence: h.confidence.get(),
        }],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::scan::Hit;
    use strata_kernel::{Confidence, EvidenceId};

    fn stored(hit: Hit) -> StoredHit {
        StoredHit { id: 5, evidence: EvidenceId::new(1), hit, volume: None, file_path: None, file_state: None, file_offset: None, occurrences: 1, disks: vec![] }
    }

    #[test]
    fn findings_become_observations() {
        let url = Hit::new("accounts.url", HitCategory::Url, 0, 0).value("https://mtgox.com/?login=gox_tester").confidence(Confidence::HIGH);
        let obs = observations(&stored(url));
        assert_eq!((obs[0].identifier.as_str(), obs[0].service.as_deref()), ("gox_tester", Some("Mt. Gox")));
        let record = serde_json::json!({"kind": "Login", "value": "Gox_Tester", "service": "mtgox.com", "source": "/p",
            "first_seen": 1_310_000_000_000_000i64, "last_seen": null, "detail": "saved browser login", "weak": false});
        let art = Hit::new("artifacts.identity", HitCategory::Identity, 0, 0).label("login").value("gox_tester").confidence(Confidence::HIGH).details(record);
        let obs = observations(&stored(art));
        assert_eq!(obs[0].identifier, "Gox_Tester");
        assert_eq!(obs[0].first_seen, Timestamp::from_unix_secs(1_310_000_000));
        assert_eq!(obs[0].source.detail, "saved browser login");
        assert_eq!(tokens("gox_tester @ mtgox.com; login=Gox_Tester"), ["gox_tester", "login", "mtgox.com"]);
    }
}
