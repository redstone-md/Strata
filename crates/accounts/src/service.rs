use crate::catalogue::{Catalogue, ServiceEntry, ServiceKind};
use serde::Serialize;

/// A classified service: a light handle on a [`ServiceEntry`] of the shared catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Service {
    pub kind: ServiceKind,
    pub name: &'static str,
    pub id: &'static str,
}

impl Service {
    fn of(entry: &'static ServiceEntry) -> Self {
        Self { kind: entry.kind(), name: entry.name(), id: entry.id() }
    }

    /// Classify free text (URL, domain, e-mail, file name, program name). Needles match on word
    /// boundaries only (`proslushivat` is not Slush pool, `vk.com` is not `qvk.community`).
    pub fn classify(text: &str) -> Option<Service> {
        Catalogue::shared().classify_text(text).map(Self::of)
    }

    /// Classify a bare host name.
    pub fn classify_host(host: &str) -> Option<Service> {
        Catalogue::shared().classify_host(host).map(Self::of)
    }

    /// Classify a URL by its host (and `host/path` entries); the query string never decides.
    pub fn classify_url(url: &str) -> Option<Service> {
        Catalogue::shared().classify_url(url).map(Self::of)
    }

    /// Classify the domain of an e-mail address (`user@bk.ru` → Mail.ru).
    pub fn classify_email(email: &str) -> Option<Service> {
        email.rsplit_once('@').and_then(|(_, domain)| Self::classify_host(domain))
    }

    pub fn by_id(id: &str) -> Option<Service> {
        Catalogue::shared().by_id(id).map(Self::of)
    }

    /// Resolve a stored service label (name, id, host or URL).
    pub fn lookup(label: &str) -> Option<Service> {
        Catalogue::shared().lookup(label).map(Self::of)
    }

    /// The catalogue entry (years, notes, domains).
    pub fn entry(self) -> &'static ServiceEntry {
        Catalogue::shared().by_id(self.id).expect("a Service always comes from the shared catalogue")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_on_word_boundaries() {
        assert!(Service::classify("news/specslujbi_smogut_proslushivat_skype.html").is_some_and(|s| s.name == "Skype"));
        assert!(Service::classify("http://slushpool.com/stats").is_some_and(|s| s.kind == ServiceKind::MiningPool));
        assert!(Service::classify("https://www.bitcointalk.org/x").is_some_and(|s| s.name == "Bitcointalk"));
        assert!(Service::classify("user@mail.ru").is_some_and(|s| s.name == "Mail.ru"));
        assert!(Service::classify("hotmail.company.net").is_none());
        assert_eq!(Service::classify_email("skype.fan@gmail.com").map(|s| s.id), Some("gmail"));
        assert!(Service::by_id("mtgox").is_some_and(|s| s.entry().years().is_some()));
    }
}
