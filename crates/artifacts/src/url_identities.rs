//! Accounts named by visited URLs: `?login=` / `&username=` parameters and profile pages of
//! catalogued services (`bitcointalk.org/index.php?action=profile;u=…`, `/user/<name>`).

use crate::results::{IdentityKind, IdentityRecord};
use strata_accounts::UrlAccounts;
use strata_timeline::{EventKind, TimelineEvent};

/// Identities implied by the URL events in `events`, dated by the visit.
pub(crate) fn url_identities(events: &[TimelineEvent]) -> Vec<IdentityRecord> {
    let mut out = Vec::new();
    for e in events.iter().filter(|e| matches!(e.kind(), EventKind::UrlVisited | EventKind::Download | EventKind::Login)) {
        for a in UrlAccounts::extract(e.title()) {
            // A login field in the URL is usually the user's own; a profile page may be anyone's.
            let weak = a.field.starts_with('/') || a.field == "u";
            let detail = if weak { format!("profile page visited ({})", a.field) } else { format!("URL field {}=", a.field) };
            out.push(IdentityRecord {
                kind: IdentityKind::of(a.kind),
                value: a.value,
                service: a.service.map(|s| s.name.to_string()),
                source: e.source().path.clone(),
                first_seen: Some(e.at()),
                last_seen: Some(e.at()),
                detail,
                weak,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::Timestamp;
    use strata_timeline::EventSource;

    #[test]
    fn visits_name_accounts() {
        let at = Timestamp::from_unix_secs(1_310_000_000).unwrap();
        let ev = |url: &str| TimelineEvent::new(at, EventKind::UrlVisited, url, EventSource::new("chrome.history", "/h"));
        let ids = url_identities(&[
            ev("https://bitcointalk.org/index.php?action=profile;u=777001"),
            ev("https://mtgox.com/?login=gox_tester"),
            ev("https://example.com/?login=nobody"),
        ]);
        assert_eq!(ids.len(), 2);
        assert!(ids[0].weak && ids[0].kind == IdentityKind::UserId && ids[0].service.as_deref() == Some("Bitcointalk"));
        assert!(!ids[1].weak && ids[1].value == "gox_tester" && ids[1].first_seen == Some(at));
    }
}
