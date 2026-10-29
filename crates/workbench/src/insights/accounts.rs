//! Turns stored identity findings, service URLs, mailboxes and account-related events into
//! [`Observation`]s for the [`AccountResolver`], each with the kind of trace it is (use or a
//! mere sighting). Plain byte-level e-mail sightings stay out: the case aggregates those.

use strata_accounts::{Account, AccountResolver, AccountSource, IdentifierKind, Observation, SourceRef, TraceKind, UrlAccounts};
use strata_case::{MailboxTrace, StoredHit};
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
        for hit in case.account_trace_hits()? {
            for obs in observations(&hit) {
                resolver.observe(obs);
            }
        }
        for trace in case.mailbox_traces()? {
            resolver.observe(mailbox_observation(&trace));
        }
        for e in events.iter().filter(|e| DATING_KINDS.contains(&e.event.kind())) {
            let source = AccountSource {
                evidence: e.evidence,
                origin: SourceRef::Event(e.id),
                detail: format!("{} event", kind_word(e.event.kind())),
                at: Some(e.event.at()),
                trace: event_trace(e.event.kind()),
            };
            resolver.date_mention(&tokens(&format!("{} {}", e.event.title(), e.event.detail())), source);
        }
        Ok(resolver.finish())
    }
}

/// What an event mentioning an identifier says about its use.
fn event_trace(kind: EventKind) -> TraceKind {
    match kind {
        EventKind::AccountSeen | EventKind::Login => TraceKind::AccountEvent,
        EventKind::FormInput => TraceKind::Autofill,
        EventKind::Cookie => TraceKind::Cookie,
        _ => TraceKind::Correspondent,
    }
}

/// The main recipient of a mailbox, or the sender of sent mail.
fn mailbox_observation(t: &MailboxTrace) -> Observation {
    let folder = t.path.rsplit(['/', '\\']).next().unwrap_or(&t.path);
    let (detail, trace) = if t.sent {
        (format!("sent {} kept in {folder}", plural(t.messages, "message")), TraceKind::SentMail)
    } else {
        (format!("receives {} of {} messages in {folder}", t.messages, t.total), TraceKind::MailboxOwner)
    };
    Observation {
        service: None,
        identifier: t.address.clone(),
        kind: IdentifierKind::Email,
        source: AccountSource { evidence: t.evidence, origin: SourceRef::File(t.path.clone()), detail, at: t.first.or(t.last), trace },
        first_seen: t.first,
        last_seen: t.last,
        confidence: trace.weight(),
    }
}

fn plural(n: u64, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
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

/// A login found byte-level: inside a URL it is a URL sighting, elsewhere a plain one.
fn byte_trace(details: &serde_json::Value) -> TraceKind {
    if str_field(details, "context") == Some("url") { TraceKind::UrlMention } else { TraceKind::Mention }
}

/// Observations carried by one stored finding.
fn observations(hit: &StoredHit) -> Vec<Observation> {
    let h = &hit.hit;
    let place = hit.file_path.as_deref().map(|p| format!(" in {p}")).unwrap_or_default();
    let source = |detail: String, at: Option<Timestamp>, trace: TraceKind| AccountSource { evidence: hit.evidence, origin: SourceRef::Hit(hit.id), detail, at, trace };
    match h.category {
        HitCategory::Url => UrlAccounts::extract(&h.value)
            .into_iter()
            .map(|a| Observation {
                service: a.service.map(|s| s.name.to_string()),
                identifier: a.value,
                kind: a.kind,
                source: source(format!("URL field {}{place}", a.field), None, TraceKind::UrlMention),
                first_seen: None,
                last_seen: None,
                confidence: h.confidence.get() * 0.8,
            })
            .collect(),
        HitCategory::Identity if h.detector == "artifacts.identity" => {
            let d = &h.details;
            let note = str_field(d, "detail").map(str::to_string).unwrap_or_else(|| format!("{}{place}", h.label));
            let weak = d.get("weak").and_then(|v| v.as_bool()).unwrap_or(false);
            let (first, last) = (ts_field(d, "first_seen"), ts_field(d, "last_seen"));
            let file = str_field(d, "source").or(hit.file_path.as_deref()).unwrap_or_default();
            let trace = TraceKind::of_artefact(str_field(d, "detail").unwrap_or_default(), str_field(d, "service"), file, weak);
            vec![Observation {
                service: str_field(d, "service").map(str::to_string),
                identifier: str_field(d, "value").unwrap_or(&h.value).to_string(),
                kind: IdentifierKind::from_label(str_field(d, "kind").unwrap_or(&h.label)),
                source: source(note, first.or(last), trace),
                first_seen: first,
                last_seen: last,
                confidence: if weak { 0.4 } else { h.confidence.get() },
            }]
        }
        HitCategory::Identity => vec![Observation {
            service: str_field(&h.details, "service").map(str::to_string),
            identifier: h.value.clone(),
            kind: IdentifierKind::from_label(&h.label),
            source: source(format!("{} on the disk{place}", h.label), None, byte_trace(&h.details)),
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
        assert_eq!(obs[0].source.trace, TraceKind::SavedPassword);
        assert_eq!(tokens("gox_tester @ mtgox.com; login=Gox_Tester"), ["gox_tester", "login", "mtgox.com"]);
    }

    #[test]
    fn traces_tell_use_from_sightings() {
        let mut url = Hit::new("accounts.login", HitCategory::Identity, 0, 0).label("login (url)").value("gox_tester");
        url.details = serde_json::json!({"service": "Mt. Gox", "context": "url"});
        assert_eq!(observations(&stored(url))[0].source.trace, TraceKind::UrlMention);
        let record = serde_json::json!({"kind": "Email", "value": "friend@example.org", "service": null,
            "source": "home/a/.thunderbird/p/ImapMail/mail.example.com/INBOX", "first_seen": null, "last_seen": null, "detail": "", "weak": false});
        let header = Hit::new("artifacts.identity", HitCategory::Identity, 0, 0).label("e-mail (artefact)").value("friend@example.org").details(record);
        assert_eq!(observations(&stored(header))[0].source.trace, TraceKind::Correspondent);
        let mailbox = MailboxTrace {
            address: "owner.test@example.com".into(),
            evidence: EvidenceId::new(1),
            path: "m/INBOX".into(),
            sent: false,
            messages: 40,
            total: 52,
            first: Timestamp::from_unix_secs(1_300_000_000),
            last: None,
        };
        let obs = mailbox_observation(&mailbox);
        assert_eq!((obs.source.trace, obs.source.detail.as_str()), (TraceKind::MailboxOwner, "receives 40 of 52 messages in INBOX"));
    }
}
