//! Firefox / Mozilla: `places.sqlite`, `downloads.sqlite`, `formhistory.sqlite`,
//! `cookies.sqlite`, `signons.sqlite`, `logins.json`.

use crate::results::Recorder;
use crate::sqlite::{RowExt, SqliteDb};
use crate::text::host_of;
use strata_kernel::{Damage, DamageKind, Timestamp};
use strata_timeline::EventKind;

/// PRTime: µs since 1970.
pub(crate) fn prtime(v: i64) -> Option<Timestamp> {
    (v > 0).then(|| Timestamp::from_unix_micros(v)).flatten()
}

fn unix_ms(v: i64) -> Option<Timestamp> {
    Timestamp::from_unix_micros(v.checked_mul(1000)?)
}

pub(crate) struct FirefoxPlaces;

impl FirefoxPlaces {
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        let has_visits = db.has_table("moz_historyvisits");
        if has_visits {
            db.each(
                "SELECT p.url, p.title, v.visit_date, v.visit_type FROM moz_historyvisits v \
                 JOIN moz_places p ON p.id = v.place_id",
                |r| {
                    let detail = format!("{} (visit type {})", r.text(1), r.int(3));
                    rec.emit(prtime(r.int(2)), EventKind::UrlVisited, r.text(0), detail);
                },
            );
        }
        if db.columns("moz_places").iter().any(|c| c == "last_visit_date") {
            let filter = if has_visits { " WHERE id NOT IN (SELECT place_id FROM moz_historyvisits)" } else { "" };
            db.each(&format!("SELECT url, title, last_visit_date, visit_count FROM moz_places{filter}"), |r| {
                let detail = format!("{} (last visit; {} visits)", r.text(1), r.int(3));
                rec.emit(prtime(r.int(2)), EventKind::UrlVisited, r.text(0), detail);
            });
        }
        if db.has_table("moz_bookmarks") {
            db.each(
                "SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk WHERE b.type = 1",
                |r| rec.emit(prtime(r.int(2)), EventKind::Other, format!("Bookmark added: {}", r.text(1)), r.text(0)),
            );
        }
        if db.has_table("moz_downloads") {
            db.each("SELECT target, source, startTime, maxBytes FROM moz_downloads", |r| {
                rec.emit(prtime(r.int(2)), EventKind::Download, r.text(0), format!("from {} ({} bytes)", r.text(1), r.int(3)));
            });
        }
    }
}

pub(crate) struct FirefoxForms;

impl FirefoxForms {
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        db.each("SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory", |r| {
            let (name, value) = (r.text(0), r.text(1));
            let (first, last) = (prtime(r.int(3)), prtime(r.int(4)));
            let title = format!("{name} = {value}");
            rec.emit(first, EventKind::FormInput, title.clone(), format!("form history, used {}×", r.int(2)));
            if last.is_some() && last != first {
                rec.emit(last, EventKind::FormInput, title, "form history last used");
            }
            if name.eq_ignore_ascii_case("searchbar-history") {
                rec.emit(first, EventKind::Search, value, "Firefox search bar");
            } else {
                super::form_identity(rec, &name, &value, first, "form history");
            }
        });
    }
}

pub(crate) struct FirefoxCookies;

impl FirefoxCookies {
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        db.each("SELECT host, name, creationTime, lastAccessed, value FROM moz_cookies", |r| {
            let (created, accessed) = (prtime(r.int(2)), prtime(r.int(3)));
            super::cookie_identity(rec, &r.text(0), &r.text(1), &r.text(4), created);
            rec.emit(created, EventKind::Cookie, r.text(0), format!("cookie {} set", r.text(1)));
            if accessed.is_some() && accessed != created {
                rec.push_low(accessed, EventKind::Cookie, r.text(0), format!("cookie {} last access", r.text(1)));
            }
        });
    }
}

pub(crate) struct FirefoxLogins;

impl FirefoxLogins {
    /// `signons.sqlite` (Firefox ≤ 31).
    pub fn parse_sqlite(db: &mut SqliteDb, rec: &mut Recorder) {
        let created = db.col_or("moz_logins", "timeCreated", "0");
        db.each(&format!("SELECT hostname, length(encryptedUsername), {created} FROM moz_logins"), |r| {
            Self::login(rec, &r.text(0), r.int(1) > 0, r.int(2), 0);
        });
    }

    /// `logins.json` (Firefox ≥ 32). Usernames are NSS-encrypted; only presence is reported.
    pub fn parse_json(data: &[u8], rec: &mut Recorder) {
        let json: serde_json::Value = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(e) => {
                rec.damage(Damage::new(DamageKind::Corrupt, None, format!("logins.json: {e}")));
                return;
            }
        };
        let logins = json.get("logins").and_then(|l| l.as_array()).map(Vec::as_slice).unwrap_or(&[]);
        for l in logins {
            let host = l.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
            let has_user = l.get("encryptedUsername").and_then(|u| u.as_str()).is_some_and(|u| !u.is_empty());
            let int = |k: &str| l.get(k).and_then(serde_json::Value::as_i64).unwrap_or(0);
            Self::login(rec, host, has_user, int("timeCreated"), int("timeLastUsed"));
        }
    }

    fn login(rec: &mut Recorder, host: &str, has_user: bool, created_ms: i64, used_ms: i64) {
        let site = host_of(host).unwrap_or_else(|| host.to_string());
        let user = if has_user { "encrypted username present (NSS, not decrypted)" } else { "no username" };
        rec.emit(unix_ms(created_ms), EventKind::AccountSeen, format!("saved login @ {site}"), format!("{host}; {user}"));
        if let Some(used) = unix_ms(used_ms) {
            rec.emit(Some(used), EventKind::Login, format!("saved login @ {site}"), format!("{host} (last used)"));
        }
    }
}
