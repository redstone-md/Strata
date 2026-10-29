//! Browser events as lists: the filter shared by every list, the segments (history, searches,
//! downloads, logins and forms, cookies) and the SQL they become. Every query goes through the
//! `events_kind (evidence_id, kind, at)` index, so it stays fast next to millions of
//! filesystem events.

use super::profile::{BrowserFamily, ProfileKey};
use rusqlite::ToSql;
use serde::Serialize;
use strata_kernel::{EvidenceId, Period, Timestamp};
use strata_timeline::EventKind;

/// A browser list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSegment {
    /// Pages visited (history databases, `index.dat`, typed URLs, recovered rows).
    #[default]
    History,
    /// Search terms typed into engines or the search bar.
    Searches,
    Downloads,
    /// Saved logins, their last use and form / autofill values.
    Logins,
    Cookies,
}

impl BrowserSegment {
    pub const ALL: [BrowserSegment; 5] = [Self::History, Self::Searches, Self::Downloads, Self::Logins, Self::Cookies];

    pub fn kinds(self) -> &'static [EventKind] {
        match self {
            Self::History => &[EventKind::UrlVisited],
            Self::Searches => &[EventKind::Search],
            Self::Downloads => &[EventKind::Download],
            Self::Logins => &[EventKind::AccountSeen, EventKind::Login, EventKind::FormInput],
            Self::Cookies => &[EventKind::Cookie],
        }
    }

    /// The segment an event kind is listed in.
    pub fn of(kind: EventKind) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.kinds().contains(&kind))
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::History => "History",
            Self::Searches => "Searches",
            Self::Downloads => "Downloads",
            Self::Logins => "Logins & forms",
            Self::Cookies => "Cookies",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::History => "history",
            Self::Searches => "searches",
            Self::Downloads => "downloads",
            Self::Logins => "logins",
            Self::Cookies => "cookies",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name().eq_ignore_ascii_case(name))
    }

    fn all_kinds() -> Vec<EventKind> {
        Self::ALL.iter().flat_map(|s| s.kinds().iter().copied()).collect()
    }
}

/// What every browser list, summary and site table is narrowed by.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BrowserFilter {
    pub evidence: Option<EvidenceId>,
    /// One profile only.
    pub profile: Option<ProfileKey>,
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
    /// Part of the URL, term, page title, value or source path (any case for ASCII).
    pub text: Option<String>,
    /// Events whose URL (or cookie host) is on this host or its `www.` twin.
    pub site: Option<String>,
    /// Only events tagged crypto-related.
    pub crypto_only: bool,
}

impl BrowserFilter {
    /// The filter inside the case's period of interest.
    pub fn within(mut self, period: Period) -> Self {
        self.from = period.later_start(self.from);
        self.to = period.earlier_end(self.to);
        self
    }
}

/// One page of a segment, oldest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BrowserQuery {
    pub filter: BrowserFilter,
    pub segment: BrowserSegment,
    /// 0 for no limit.
    pub limit: usize,
    pub offset: usize,
}

/// A `WHERE` clause with its positional arguments.
pub(crate) struct Clause {
    pub sql: String,
    pub args: Vec<Box<dyn ToSql>>,
}

impl Clause {
    /// Browser events of `kinds` matching `f`.
    pub fn new(f: &BrowserFilter, kinds: &[EventKind]) -> Self {
        let mut c = Self { sql: String::new(), args: Vec::new() };
        match f.profile.as_ref().map(|p| p.evidence).or(f.evidence) {
            Some(e) => c.push("evidence_id = ?{n}", Box::new(e.get())),
            None => c.sql += "evidence_id IN (SELECT id FROM evidence)",
        }
        let kinds: Vec<String> = kinds.iter().map(|k| format!("'{k:?}'")).collect();
        c.sql += &format!(" AND kind IN ({})", kinds.join(","));
        match &f.profile {
            Some(p) => {
                c.sql += &format!(" AND {}", p.family.sql());
                if !p.dir.is_empty() {
                    let prefix = format!("{}/", p.dir);
                    c.push(" AND substr(path, 1, ?{n}", Box::new(prefix.chars().count() as i64));
                    c.push(") = ?{n}", Box::new(prefix));
                }
            }
            None => c.sql += &format!(" AND {}", BrowserFamily::any_sql()),
        }
        if let Some(t) = f.from {
            c.push(" AND at >= ?{n}", Box::new(t.unix_micros()));
        }
        if let Some(t) = f.to {
            c.push(" AND at < ?{n}", Box::new(t.unix_micros()));
        }
        if let Some(t) = f.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            c.push(" AND (title LIKE ?{n} OR data LIKE ?{n})", Box::new(format!("%{t}%")));
        }
        if let Some(host) = f.site.as_deref().map(super::sites::site_key).filter(|h| !h.is_empty()) {
            c.push(
                " AND (instr(lower(title) || '/', '://' || ?{n} || '/') > 0 OR instr(lower(title) || '/', '://www.' || ?{n} || '/') > 0 \
                 OR instr(ltrim(lower(title), '.') || '/', ?{n} || '/') = 1 OR instr(ltrim(lower(title), '.') || '/', 'www.' || ?{n} || '/') = 1)",
                Box::new(host),
            );
        }
        if f.crypto_only {
            c.sql += " AND crypto = 1";
        }
        c
    }

    /// Every browser kind.
    pub fn all(f: &BrowserFilter) -> Self {
        Self::new(f, &BrowserSegment::all_kinds())
    }

    /// `{n}` in `clause` becomes the index of the argument just pushed.
    fn push(&mut self, clause: &str, value: Box<dyn ToSql>) {
        self.args.push(value);
        self.sql += &clause.replace("{n}", &self.args.len().to_string());
    }

    pub fn params(&self) -> impl rusqlite::Params + '_ {
        rusqlite::params_from_iter(self.args.iter().map(|a| a.as_ref()))
    }
}
