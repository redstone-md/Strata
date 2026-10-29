//! One browser event of a list, and the parts of it the parsers pack into title and detail
//! (`user @ site`, `field = value`, `from <url> (<n> bytes)`).

use super::profile::{BrowserFamily, ProfileKey};
use super::sites::site_key;
use serde::Serialize;
use strata_kernel::EvidenceId;
use strata_timeline::{EventKind, TimelineEvent};

/// A browser event with where it was read.
#[derive(Debug, Clone, Serialize)]
pub struct BrowserRow {
    pub id: i64,
    pub evidence: EvidenceId,
    pub family: BrowserFamily,
    pub event: TimelineEvent,
}

/// A saved login, its use, or a remembered form value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// `saved login`, `login used` or `form value`.
    pub what: &'static str,
    /// Host the login is for; empty for form history (browsers do not keep the page).
    pub site: String,
    /// Form field name; empty for logins.
    pub field: String,
    /// User name or field value; empty when the browser keeps it encrypted.
    pub value: String,
}

/// Where a download came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadSource {
    pub url: String,
    pub bytes: Option<u64>,
}

/// Firefox names a login it cannot show the user of this way.
const ENCRYPTED_LOGIN: &str = "saved login";

impl BrowserRow {
    pub fn profile(&self) -> ProfileKey {
        ProfileKey::locate(self.evidence, self.family, &self.event.source().path)
    }

    /// Read from a deleted file, a freed database row or carved bytes.
    pub fn deleted(&self) -> bool {
        self.event.source().deleted
    }

    /// Login and form rows as site, field and value.
    pub fn credential(&self) -> Option<Credential> {
        let title = self.event.title();
        let what = match self.event.kind() {
            EventKind::FormInput => {
                let (field, value) = title.split_once(" = ").unwrap_or((title, ""));
                return Some(Credential { what: "form value", site: String::new(), field: field.to_string(), value: value.to_string() });
            }
            EventKind::AccountSeen => "saved login",
            EventKind::Login => "login used",
            _ => return None,
        };
        let (user, site) = match title.rsplit_once(" @ ") {
            Some((user, site)) => (if user == ENCRYPTED_LOGIN { "" } else { user }, site.to_string()),
            None => ("", site_key(title)),
        };
        Some(Credential { what, site, field: String::new(), value: user.to_string() })
    }

    /// The URL and size of a download (`from <url> (<n> bytes)` in the detail).
    pub fn download_source(&self) -> Option<DownloadSource> {
        if self.event.kind() != EventKind::Download {
            return None;
        }
        let rest = self.event.detail().strip_prefix("from ")?;
        let (url, size) = rest.rsplit_once(" (").unwrap_or((rest, ""));
        let bytes = size.strip_suffix(" bytes)").and_then(|n| n.parse().ok()).filter(|n| *n > 0);
        Some(DownloadSource { url: url.to_string(), bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::Timestamp;
    use strata_timeline::EventSource;

    fn row(kind: EventKind, title: &str, detail: &str) -> BrowserRow {
        let at = Timestamp::from_unix_secs(1_300_000_000).unwrap();
        let event = TimelineEvent::new(at, kind, title, EventSource::new("chrome.login_data", "x/Login Data")).with_detail(detail);
        BrowserRow { id: 1, evidence: EvidenceId::new(1), family: BrowserFamily::Chromium, event }
    }

    #[test]
    fn credentials() {
        let c = row(EventKind::AccountSeen, "tester @ shop.example.com", "").credential().unwrap();
        assert_eq!((c.what, c.site.as_str(), c.value.as_str()), ("saved login", "shop.example.com", "tester"));
        let c = row(EventKind::Login, "saved login @ example.org", "").credential().unwrap();
        assert_eq!((c.what, c.site.as_str(), c.value.as_str()), ("login used", "example.org", ""));
        let c = row(EventKind::AccountSeen, "https://www.example.net/login", "").credential().unwrap();
        assert_eq!(c.site, "example.net");
        let c = row(EventKind::FormInput, "email = a = b", "").credential().unwrap();
        assert_eq!((c.field.as_str(), c.value.as_str()), ("email", "a = b"));
        assert!(row(EventKind::Cookie, "x", "").credential().is_none());
    }

    #[test]
    fn downloads() {
        let d = row(EventKind::Download, "C:/x (1).zip", "from https://example.com/x (1).zip (42 bytes)").download_source().unwrap();
        assert_eq!((d.url.as_str(), d.bytes), ("https://example.com/x (1).zip", Some(42)));
        assert_eq!(row(EventKind::Download, "f", "from  (0 bytes)").download_source().unwrap().bytes, None);
        assert!(row(EventKind::Download, "f", "odd").download_source().is_none());
    }
}
