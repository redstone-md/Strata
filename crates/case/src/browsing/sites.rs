//! Browser events folded by site and by profile: visits per host with the catalogued service
//! behind it, cookies per host, and what each profile holds.

use super::profile::ProfileKey;
use super::query::BrowserSegment;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use strata_accounts::{Service, host_of};
use strata_kernel::{EvidenceId, Timestamp};
use strata_timeline::EventKind;

/// Top sites kept per profile.
const TOP_SITES: usize = 5;
/// Cookie names kept per site.
const COOKIE_NAMES: usize = 12;

/// The host a site is grouped under: lower case, no leading dot, no `www.`. Takes a URL, a
/// cookie host (`.example.com`) or IE's `host/path`.
pub fn site_key(url_or_host: &str) -> String {
    let host = host_of(url_or_host).unwrap_or_default();
    host.strip_prefix("www.").map(str::to_string).unwrap_or(host)
}

/// First and last time, widened one event at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub first: Timestamp,
    pub last: Timestamp,
}

impl Span {
    fn widen(span: &mut Option<Span>, first: Timestamp, last: Timestamp) {
        *span = Some(match *span {
            Some(s) => Span { first: s.first.min(first), last: s.last.max(last) },
            None => Span { first, last },
        });
    }
}

/// Visits to one host, on every disk and profile in the filter.
#[derive(Debug, Clone, Serialize)]
pub struct SiteSummary {
    pub host: String,
    pub visits: u64,
    /// Visits the parsers tagged crypto-related (a wallet page, a faucet path).
    pub crypto_visits: u64,
    /// Visits read from deleted files or freed rows.
    pub deleted: u64,
    pub span: Span,
    pub disks: Vec<EvidenceId>,
    /// The catalogued service the host belongs to.
    pub service: Option<Service>,
}

impl SiteSummary {
    /// An exchange, wallet, faucet, pool, forum… of the catalogue, or crypto-tagged visits.
    pub fn is_crypto(&self) -> bool {
        self.service.is_some_and(|s| s.kind.is_crypto()) || self.crypto_visits > 0
    }
}

/// Cookies one host set, across the filter.
#[derive(Debug, Clone, Serialize)]
pub struct CookieSite {
    pub host: String,
    /// Cookie events (set and last access).
    pub events: u64,
    /// Cookie names seen, sorted, at most a dozen.
    pub names: Vec<String>,
    pub span: Span,
    pub disks: Vec<EvidenceId>,
    pub service: Option<Service>,
}

impl CookieSite {
    pub fn is_crypto(&self) -> bool {
        self.service.is_some_and(|s| s.kind.is_crypto())
    }
}

/// What one browser profile holds.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub key: ProfileKey,
    /// Events per segment, in [`BrowserSegment::ALL`] order.
    pub counts: [u64; 5],
    pub deleted_visits: u64,
    /// Visits when there are any, else every event of the profile.
    pub span: Option<Span>,
    /// Most visited hosts, most first.
    pub top_sites: Vec<(String, u64)>,
}

impl ProfileSummary {
    pub fn count(&self, segment: BrowserSegment) -> u64 {
        BrowserSegment::ALL.iter().position(|s| *s == segment).map_or(0, |i| self.counts[i])
    }
}

/// Profiles and sites of the filter, the browser screen's overview.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BrowserOverview {
    pub profiles: Vec<ProfileSummary>,
    /// Crypto-related first, then by visits.
    pub sites: Vec<SiteSummary>,
}

impl BrowserOverview {
    pub fn total(&self, segment: BrowserSegment) -> u64 {
        self.profiles.iter().map(|p| p.count(segment)).sum()
    }
}

/// Builds [`ProfileSummary`]s from per-file counts and the visits' hosts.
#[derive(Default)]
pub(crate) struct ProfileTally {
    profiles: HashMap<ProfileKey, (ProfileSummary, Option<Span>, HashMap<String, u64>)>,
}

impl ProfileTally {
    fn entry(&mut self, key: ProfileKey) -> &mut (ProfileSummary, Option<Span>, HashMap<String, u64>) {
        self.profiles.entry(key.clone()).or_insert_with(|| {
            (ProfileSummary { key, counts: [0; 5], deleted_visits: 0, span: None, top_sites: Vec::new() }, None, HashMap::new())
        })
    }

    /// `n` events of `kind` read from one file, `deleted` of them deleted, between two times.
    pub fn count(&mut self, key: ProfileKey, kind: EventKind, n: u64, deleted: u64, first: Timestamp, last: Timestamp) {
        let Some(segment) = BrowserSegment::of(kind) else { return };
        let (summary, any_span, _) = self.entry(key);
        if let Some(i) = BrowserSegment::ALL.iter().position(|s| *s == segment) {
            summary.counts[i] += n;
        }
        if segment == BrowserSegment::History {
            summary.deleted_visits += deleted;
            Span::widen(&mut summary.span, first, last);
        }
        Span::widen(any_span, first, last);
    }

    pub fn visit(&mut self, key: ProfileKey, host: &str) {
        if !host.is_empty() {
            *self.entry(key).2.entry(host.to_string()).or_default() += 1;
        }
    }

    pub fn finish(self) -> Vec<ProfileSummary> {
        let mut out: Vec<ProfileSummary> = self
            .profiles
            .into_values()
            .map(|(mut s, any_span, hosts)| {
                s.span = s.span.or(any_span);
                let mut top: Vec<(String, u64)> = hosts.into_iter().collect();
                top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                top.truncate(TOP_SITES);
                s.top_sites = top;
                s
            })
            .collect();
        out.sort_by(|a, b| a.key.evidence.cmp(&b.key.evidence).then(b.count(BrowserSegment::History).cmp(&a.count(BrowserSegment::History))).then_with(|| a.key.cmp(&b.key)));
        out
    }
}

/// Builds [`SiteSummary`]s one visit at a time.
#[derive(Default)]
pub(crate) struct SiteTally {
    sites: HashMap<String, SiteSummary>,
}

impl SiteTally {
    pub fn visit(&mut self, host: &str, evidence: EvidenceId, at: Timestamp, crypto: bool, deleted: bool) {
        if host.is_empty() {
            return;
        }
        let site = self.sites.entry(host.to_string()).or_insert_with(|| SiteSummary {
            host: host.to_string(),
            visits: 0,
            crypto_visits: 0,
            deleted: 0,
            span: Span { first: at, last: at },
            disks: Vec::new(),
            service: Service::classify_host(host),
        });
        site.visits += 1;
        site.crypto_visits += u64::from(crypto);
        site.deleted += u64::from(deleted);
        site.span = Span { first: site.span.first.min(at), last: site.span.last.max(at) };
        if !site.disks.contains(&evidence) {
            site.disks.push(evidence);
        }
    }

    pub fn finish(self, crypto_only: bool) -> Vec<SiteSummary> {
        let mut out: Vec<SiteSummary> = self.sites.into_values().filter(|s| !crypto_only || s.is_crypto()).collect();
        out.sort_by(|a, b| b.is_crypto().cmp(&a.is_crypto()).then(b.visits.cmp(&a.visits)).then_with(|| a.host.cmp(&b.host)));
        out
    }
}

/// Builds [`CookieSite`]s one cookie event at a time.
#[derive(Default)]
pub(crate) struct CookieTally {
    sites: HashMap<String, (CookieSite, BTreeSet<String>)>,
}

impl CookieTally {
    /// A cookie event: its title is the host, its detail `cookie <name> set|last access`.
    pub fn add(&mut self, evidence: EvidenceId, title: &str, detail: &str, at: Timestamp) {
        let host = site_key(title);
        if host.is_empty() {
            return;
        }
        let (site, names) = self.sites.entry(host.clone()).or_insert_with(|| {
            let service = Service::classify_host(&host);
            (CookieSite { host, events: 0, names: Vec::new(), span: Span { first: at, last: at }, disks: Vec::new(), service }, BTreeSet::new())
        });
        site.events += 1;
        site.span = Span { first: site.span.first.min(at), last: site.span.last.max(at) };
        if !site.disks.contains(&evidence) {
            site.disks.push(evidence);
        }
        if let Some(name) = cookie_name(detail) {
            names.insert(name.to_string());
        }
    }

    pub fn finish(self, crypto_only: bool) -> Vec<CookieSite> {
        let mut out: Vec<CookieSite> = self
            .sites
            .into_values()
            .map(|(mut site, names)| {
                site.names = names.into_iter().take(COOKIE_NAMES).collect();
                site
            })
            .filter(|s| !crypto_only || s.is_crypto())
            .collect();
        out.sort_by(|a, b| b.is_crypto().cmp(&a.is_crypto()).then(b.events.cmp(&a.events)).then_with(|| a.host.cmp(&b.host)));
        out
    }
}

/// `cookie sid set` → `sid`.
fn cookie_name(detail: &str) -> Option<&str> {
    let rest = detail.strip_prefix("cookie ")?;
    let name = rest.strip_suffix(" set").or_else(|| rest.strip_suffix(" last access"))?;
    (!name.is_empty()).then_some(name)
}
