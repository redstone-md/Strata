//! The service catalogue: every known exchange, faucet, pool, wallet, forum, payment system,
//! mail and messenger, loaded once from `data/services.toml` (embedded in the binary).

mod entry;
mod kind;
mod matcher;

pub use entry::{ServiceEntry, Years};
pub use kind::ServiceKind;

use matcher::{Found, Matcher, NeedleKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

const EMBEDDED: &str = include_str!("../../data/services.toml");

#[derive(Deserialize)]
struct CatalogueFile {
    version: u32,
    #[serde(default)]
    signup_subjects: Vec<String>,
    #[serde(default)]
    money_subjects: Vec<String>,
    service: Vec<ServiceEntry>,
}

pub struct Catalogue {
    version: u32,
    entries: Vec<ServiceEntry>,
    by_key: HashMap<String, usize>,
    matcher: Matcher,
    signup_subjects: Vec<String>,
    money_subjects: Vec<String>,
}

impl Catalogue {
    /// The embedded catalogue, parsed on first use.
    pub fn shared() -> &'static Catalogue {
        static SHARED: OnceLock<Catalogue> = OnceLock::new();
        SHARED.get_or_init(|| Catalogue::parse(EMBEDDED).expect("embedded services.toml is valid (checked by tests)"))
    }

    /// Parse a catalogue file. Rejects duplicate ids and duplicate domains.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: CatalogueFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut by_key = HashMap::new();
        let mut patterns = Vec::new();
        let mut seen_needles: HashMap<String, usize> = HashMap::new();
        for (i, e) in file.service.iter().enumerate() {
            if by_key.insert(e.id().to_string(), i).is_some() {
                return Err(format!("duplicate service id {}", e.id()));
            }
            by_key.entry(e.name().to_lowercase()).or_insert(i);
            for d in e.domains() {
                let d = d.to_lowercase();
                if let Some(other) = seen_needles.insert(d.clone(), i).filter(|o| *o != i) {
                    return Err(format!("domain {d} listed by {} and {}", file.service[other].id(), e.id()));
                }
                let kind = if d.contains('/') { NeedleKind::Path } else { NeedleKind::Domain };
                patterns.push((d, i, kind));
            }
            for k in e.keywords() {
                patterns.push((k.to_lowercase(), i, NeedleKind::Keyword));
            }
        }
        let lower = |v: Vec<String>| v.into_iter().map(|s| s.to_lowercase()).collect();
        Ok(Self {
            version: file.version,
            matcher: Matcher::new(patterns),
            entries: file.service,
            by_key,
            signup_subjects: lower(file.signup_subjects),
            money_subjects: lower(file.money_subjects),
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn entries(&self) -> &[ServiceEntry] {
        &self.entries
    }

    pub fn by_id(&self, id: &str) -> Option<&ServiceEntry> {
        self.by_key.get(id).and_then(|&i| self.entries.get(i)).filter(|e| e.id() == id)
    }

    /// Resolve a free-form service label (id, display name, host, URL or e-mail).
    pub fn lookup(&self, label: &str) -> Option<&ServiceEntry> {
        let key = label.trim().to_lowercase();
        if let Some(e) = self.by_key.get(&key).and_then(|&i| self.entries.get(i)) {
            return Some(e);
        }
        self.classify_text(&key)
    }

    fn entry(&self, found: Option<Found>) -> Option<&ServiceEntry> {
        found.and_then(|f| self.entries.get(f.entry))
    }

    /// Any domain, path or keyword anywhere in free text (event titles, file names, e-mails).
    pub fn classify_text(&self, text: &str) -> Option<&ServiceEntry> {
        with_folded(text, |hay| self.entry(self.matcher.best(hay, |_| true)))
    }

    /// Every distinct service mentioned in `text`, most specific first.
    pub fn all_in_text(&self, text: &str) -> Vec<&ServiceEntry> {
        with_folded(text, |hay| {
            let mut found: Vec<Found> = self.matcher.find_all(hay).collect();
            found.sort_by_key(|f| std::cmp::Reverse((f.kind, f.end - f.start)));
            let mut out: Vec<&ServiceEntry> = Vec::new();
            for f in found {
                if let Some(e) = self.entries.get(f.entry).filter(|e| !out.iter().any(|o| o.id() == e.id())) {
                    out.push(e);
                }
            }
            out
        })
    }

    /// A bare host name: domains only, plus the generic words of `host_keywords` entries.
    pub fn classify_host(&self, host: &str) -> Option<&ServiceEntry> {
        let accept = |f: &Found| match f.kind {
            NeedleKind::Domain => true,
            NeedleKind::Path => false,
            NeedleKind::Keyword => self.entries.get(f.entry).is_some_and(ServiceEntry::host_keywords),
        };
        self.entry(self.matcher.best(host.as_bytes(), accept))
    }

    /// A URL: the host decides, except `host/path` entries that name a section of a generic
    /// site (`reddit.com/r/bitcoin`). Query strings never decide the service.
    pub fn classify_url(&self, url: &str) -> Option<&ServiceEntry> {
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
        let rest = &rest[..path_end];
        let host_end = rest.find('/').unwrap_or(rest.len());
        let accept = |f: &Found| {
            f.start < host_end
                && match f.kind {
                    NeedleKind::Path => true,
                    NeedleKind::Domain => f.end <= host_end,
                    NeedleKind::Keyword => f.end <= host_end && self.entries.get(f.entry).is_some_and(ServiceEntry::host_keywords),
                }
        };
        self.entry(self.matcher.best(rest.as_bytes(), accept))
    }

    /// The domain mentioned last in `text` (closest to whatever follows it): the service a
    /// form value right after the text most likely belongs to.
    pub fn last_domain_in(&self, text: &str) -> Option<&ServiceEntry> {
        let found = self.matcher.find_all(text.as_bytes()).filter(|f| f.kind != NeedleKind::Keyword);
        self.entry(found.max_by(|a, b| a.end.cmp(&b.end).then((a.kind, a.end - a.start).cmp(&(b.kind, b.end - b.start)))))
    }

    /// A mail subject that announces a new account, a confirmation or a password reset.
    pub fn is_signup_subject(&self, subject: &str) -> bool {
        let s = subject.to_lowercase();
        self.signup_subjects.iter().any(|w| s.contains(w.as_str()))
    }

    /// A mail subject about a withdrawal, deposit or payout.
    pub fn is_money_subject(&self, subject: &str) -> bool {
        let s = subject.to_lowercase();
        self.money_subjects.iter().any(|w| s.contains(w.as_str()))
    }

    /// Entry count per kind, in display order.
    pub fn count_by_kind(&self) -> Vec<(ServiceKind, usize)> {
        ServiceKind::ALL
            .iter()
            .map(|k| (*k, self.entries.iter().filter(|e| e.kind() == *k).count()))
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}

/// Run `f` over `text` as bytes, lowercased first when it has non-ASCII letters (Cyrillic
/// keywords); ASCII case is folded by the matcher itself.
fn with_folded<T>(text: &str, f: impl FnOnce(&[u8]) -> T) -> T {
    if text.is_ascii() { f(text.as_bytes()) } else { f(text.to_lowercase().as_bytes()) }
}

#[cfg(test)]
mod tests;
