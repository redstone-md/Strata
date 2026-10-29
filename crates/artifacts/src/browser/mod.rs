//! Browser artefacts. SQLite databases are routed by schema (so carved and renamed files work),
//! with a raw page-walk fallback and deleted-row recovery for history databases.

mod chrome;
mod firefox;
mod index_dat;
mod opera;

pub(crate) use firefox::FirefoxLogins;
pub(crate) use index_dat::IndexDat;
pub(crate) use opera::{OperaGlobalHistory, OperaTypedHistory};

use crate::results::{ArtifactResults, Recorder};
use crate::sqlite::{RawUrlScanner, SqliteDb, SqlitePages, TimeEncoding};
use chrome::{ChromeCookies, ChromeHistory, ChromeLogins, ChromeWebData};
use firefox::{FirefoxCookies, FirefoxForms, FirefoxPlaces};
use std::collections::HashSet;
use strata_kernel::{Confidence, Damage, DamageKind};
use strata_timeline::EventKind;

#[cfg(test)]
pub(crate) use index_dat::testutil as index_dat_testutil;

/// Which browser database a SQLite file is, decided from its tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserDb {
    ChromeHistory,
    ChromeLogins,
    ChromeWebData,
    ChromeCookies,
    FirefoxPlaces,
    FirefoxForms,
    FirefoxCookies,
    FirefoxSignons,
    Unknown,
}

impl BrowserDb {
    fn detect(db: &SqliteDb) -> Self {
        let tables = db.tables();
        let has = |t: &str| tables.iter().any(|x| x == t);
        if has("urls") && (has("visits") || has("keyword_search_terms")) {
            Self::ChromeHistory
        } else if has("logins") {
            Self::ChromeLogins
        } else if has("autofill") || has("autofill_profiles") {
            Self::ChromeWebData
        } else if has("cookies") {
            Self::ChromeCookies
        } else if has("moz_places") || has("moz_downloads") {
            Self::FirefoxPlaces
        } else if has("moz_formhistory") {
            Self::FirefoxForms
        } else if has("moz_cookies") {
            Self::FirefoxCookies
        } else if has("moz_logins") {
            Self::FirefoxSignons
        } else {
            Self::Unknown
        }
    }

    /// Guess from a file name when SQLite cannot read the schema.
    fn from_name(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.contains("places") {
            Self::FirefoxPlaces
        } else if n.contains("history") {
            Self::ChromeHistory
        } else {
            Self::Unknown
        }
    }

    fn artifact(self) -> &'static str {
        match self {
            Self::ChromeHistory => "chrome.history",
            Self::ChromeLogins => "chrome.login_data",
            Self::ChromeWebData => "chrome.web_data",
            Self::ChromeCookies => "chrome.cookies",
            Self::FirefoxPlaces => "firefox.places",
            Self::FirefoxForms => "firefox.formhistory",
            Self::FirefoxCookies => "firefox.cookies",
            Self::FirefoxSignons => "firefox.signons",
            Self::Unknown => "sqlite",
        }
    }

    fn time_encoding(self) -> TimeEncoding {
        match self {
            Self::FirefoxPlaces | Self::FirefoxForms | Self::FirefoxCookies | Self::FirefoxSignons => TimeEncoding::PrTime,
            _ => TimeEncoding::Webkit,
        }
    }

    fn is_history(self) -> bool {
        matches!(self, Self::ChromeHistory | Self::FirefoxPlaces | Self::Unknown)
    }
}

/// Parse any browser SQLite database (live, deleted or carved).
pub(crate) fn parse_sqlite(name_hint: &str, data: &[u8]) -> ArtifactResults {
    let mut db = match SqliteDb::open(data) {
        Ok(db) => db,
        Err(e) => return raw_fallback(BrowserDb::from_name(name_hint), data, &e),
    };
    let kind = BrowserDb::detect(&db);
    let mut rec = Recorder::new(kind.artifact());
    match kind {
        BrowserDb::ChromeHistory => ChromeHistory::parse(&mut db, &mut rec),
        BrowserDb::ChromeLogins => ChromeLogins::parse(&mut db, &mut rec),
        BrowserDb::ChromeWebData => ChromeWebData::parse(&mut db, &mut rec),
        BrowserDb::ChromeCookies => ChromeCookies::parse(&mut db, &mut rec),
        BrowserDb::FirefoxPlaces => FirefoxPlaces::parse(&mut db, &mut rec),
        BrowserDb::FirefoxForms => FirefoxForms::parse(&mut db, &mut rec),
        BrowserDb::FirefoxCookies => FirefoxCookies::parse(&mut db, &mut rec),
        BrowserDb::FirefoxSignons => FirefoxLogins::parse_sqlite(&mut db, &mut rec),
        BrowserDb::Unknown => {}
    }
    for d in db.take_damage() {
        rec.damage(d);
    }
    let mut out = rec.finish();
    if kind.is_history() && kind != BrowserDb::Unknown {
        recover_deleted(kind, data, &mut out);
    }
    out
}

/// SQLite refused the file: pull URLs and nearby timestamps straight from the pages.
fn raw_fallback(kind: BrowserDb, data: &[u8], why: &str) -> ArtifactResults {
    let mut rec = Recorder::new(raw_artifact(kind));
    rec.damage(Damage::new(DamageKind::Corrupt, None, format!("SQLite refused the file ({why}); raw page-walk used")));
    let scanner = RawUrlScanner::new(kind.time_encoding());
    for hit in scanner.scan(data, 0, data.len()) {
        match rec.make(hit.time, EventKind::UrlVisited, hit.url.clone()) {
            Some(e) => rec.push(e.with_detail("raw page-walk (damaged database)").with_confidence(Confidence::LOW).with_tag("raw")),
            None => rec.fact("url", hit.url),
        }
    }
    rec.finish()
}

fn raw_artifact(kind: BrowserDb) -> &'static str {
    match kind {
        BrowserDb::FirefoxPlaces => "firefox.places.raw",
        BrowserDb::ChromeHistory => "chrome.history.raw",
        _ => "sqlite.raw",
    }
}

/// Deleted `urls`/`moz_places` rows: URLs in freelist pages, page gaps and freeblocks that are
/// not among the live rows.
fn recover_deleted(kind: BrowserDb, data: &[u8], out: &mut ArtifactResults) {
    let live: HashSet<String> = out.events.iter().map(|e| e.title().to_string()).collect();
    let scanner = RawUrlScanner::new(kind.time_encoding());
    let mut rec = Recorder::new(kind.artifact());
    let mut seen = HashSet::new();
    for (start, end) in SqlitePages::new(data).slack_regions() {
        for hit in scanner.scan(data, start, end) {
            if live.contains(&hit.url) || !seen.insert((hit.url.clone(), hit.time)) {
                continue;
            }
            match rec.make(hit.time, EventKind::UrlVisited, hit.url.clone()) {
                Some(mut e) => {
                    e.set_origin("", true);
                    rec.push(e.with_detail("recovered deleted row").with_confidence(Confidence::LOW).with_tag("recovered"));
                }
                None => rec.fact("recovered_url", hit.url),
            }
        }
    }
    out.merge(rec.finish());
}

#[cfg(test)]
mod tests;
