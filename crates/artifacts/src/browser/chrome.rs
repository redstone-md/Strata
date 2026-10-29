//! Chromium-family databases (Chrome, Chromium, Opera Blink, Yandex, Edge): `History`,
//! `Login Data`, `Web Data`, `Cookies`.

use crate::results::{IdentityKind, Recorder};
use crate::sqlite::{RowExt, SqliteDb};
use crate::text::{host_of, is_email};
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

/// Chrome stores WebKit µs; a few old columns (`downloads.start_time` before v26,
/// `logins.date_created` in early builds, `autofill_dates`) hold Unix seconds.
pub(crate) fn chrome_time(v: i64) -> Option<Timestamp> {
    if v <= 0 {
        None
    } else if v < 100_000_000_000 {
        Timestamp::from_unix_secs(v)
    } else {
        Timestamp::from_webkit(v)
    }
}

/// Page transition core type (low byte of `visits.transition`).
fn transition(t: i64) -> &'static str {
    match t & 0xff {
        0 => "link",
        1 => "typed",
        2 => "auto bookmark",
        3 | 4 => "subframe",
        5 => "generated",
        6 => "start page",
        7 => "form submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword generated",
        _ => "other",
    }
}

pub(crate) struct ChromeHistory;

impl ChromeHistory {
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        if db.has_table("visits") {
            db.each(
                "SELECT u.url, u.title, v.visit_time, v.transition FROM visits v JOIN urls u ON u.id = v.url",
                |r| {
                    let detail = format!("{} ({})", r.text(1), transition(r.int(3)));
                    rec.emit(chrome_time(r.int(2)), EventKind::UrlVisited, r.text(0), detail);
                },
            );
        }
        let orphan_filter = if db.has_table("visits") { " WHERE id NOT IN (SELECT url FROM visits)" } else { "" };
        let sql = format!("SELECT url, title, last_visit_time, visit_count, typed_count FROM urls{orphan_filter}");
        db.each(&sql, |r| {
            let detail = format!("{} (last visit; {} visits, {} typed)", r.text(1), r.int(3), r.int(4));
            rec.emit(chrome_time(r.int(2)), EventKind::UrlVisited, r.text(0), detail);
        });
        Self::downloads(db, rec);
        if db.has_table("keyword_search_terms") {
            db.each(
                "SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k LEFT JOIN urls u ON u.id = k.url_id",
                |r| rec.emit(chrome_time(r.int(2)), EventKind::Search, r.text(0), r.text(1)),
            );
        }
    }

    fn downloads(db: &mut SqliteDb, rec: &mut Recorder) {
        if !db.has_table("downloads") {
            return;
        }
        let cols = db.columns("downloads");
        let sql = if cols.iter().any(|c| c == "target_path") {
            let url = if db.has_table("downloads_url_chains") {
                "(SELECT url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY chain_index DESC LIMIT 1)"
            } else {
                "''"
            };
            format!("SELECT d.target_path, {url}, d.start_time, d.end_time, d.total_bytes FROM downloads d")
        } else {
            "SELECT full_path, url, start_time, end_time, total_bytes FROM downloads".to_string()
        };
        db.each(&sql, |r| {
            let detail = format!("from {} ({} bytes)", r.text(1), r.int(4));
            rec.emit(chrome_time(r.int(2)), EventKind::Download, r.text(0), detail);
        });
    }
}

pub(crate) struct ChromeLogins;

impl ChromeLogins {
    /// Saved logins. Passwords are DPAPI blobs: only their length is reported.
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        let last_used = db.col_or("logins", "date_last_used", "0");
        let sql = format!("SELECT origin_url, signon_realm, username_value, password_value, date_created, {last_used} FROM logins");
        db.each(&sql, |r| {
            let (origin, user) = (r.text(0), r.text(2));
            let site = host_of(&origin).or_else(|| host_of(&r.text(1))).unwrap_or_default();
            let created = chrome_time(r.int(4));
            let pw = match r.blob_len(3) {
                0 => "no password stored".to_string(),
                n => format!("password: DPAPI-encrypted blob, {n} bytes (not decrypted)"),
            };
            let title = if user.is_empty() { origin.clone() } else { format!("{user} @ {site}") };
            rec.emit(created, EventKind::AccountSeen, title.clone(), format!("{origin}; {pw}"));
            if let Some(used) = chrome_time(r.int(5)) {
                rec.emit(Some(used), EventKind::Login, title, format!("{origin} (last used)"));
            }
            let kind = if is_email(&user) { IdentityKind::Email } else { IdentityKind::Login };
            let service = (!site.is_empty()).then_some(site.as_str());
            rec.identity_noted(kind, &user, service, created, "saved browser login");
        });
    }
}

pub(crate) struct ChromeWebData;

impl ChromeWebData {
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        if db.has_table("autofill") {
            let cols = db.columns("autofill");
            let sql = if cols.iter().any(|c| c == "date_created") {
                "SELECT name, value, date_created, date_last_used, count FROM autofill".to_string()
            } else if db.has_table("autofill_dates") {
                "SELECT a.name, a.value, min(d.date_created), max(d.date_created), a.count FROM autofill a \
                 LEFT JOIN autofill_dates d ON d.pair_id = a.pair_id GROUP BY a.pair_id"
                    .to_string()
            } else {
                "SELECT name, value, 0, 0, count FROM autofill".to_string()
            };
            db.each(&sql, |r| Self::field(rec, &r.text(0), &r.text(1), r.int(2), r.int(3), r.int(4)));
        }
        if db.has_table("autofill_profile_emails") {
            db.each("SELECT email FROM autofill_profile_emails", |r| rec.identity_noted(IdentityKind::Email, &r.text(0), None, None, "autofill profile"));
        }
        if db.has_table("autofill_profile_phones") {
            db.each("SELECT number FROM autofill_profile_phones", |r| rec.identity_noted(IdentityKind::Phone, &r.text(0), None, None, "autofill profile"));
        }
        if db.has_table("autofill_profiles") && db.columns("autofill_profiles").iter().any(|c| c == "email") {
            db.each("SELECT email, date_modified FROM autofill_profiles", |r| {
                rec.identity_noted(IdentityKind::Email, &r.text(0), None, chrome_time(r.int(1)), "autofill profile")
            });
        }
    }

    fn field(rec: &mut Recorder, name: &str, value: &str, created: i64, last: i64, count: i64) {
        let (first, last) = (chrome_time(created), chrome_time(last));
        let title = format!("{name} = {value}");
        rec.emit(first, EventKind::FormInput, title.clone(), format!("autofill, used {count}×"));
        if last.is_some() && last != first {
            rec.emit(last, EventKind::FormInput, title, "autofill last used");
        }
        super::form_identity(rec, name, value, first, "autofill");
    }
}

pub(crate) struct ChromeCookies;

impl ChromeCookies {
    /// Cookie names and hosts; a value is read only when the cookie is named like a login
    /// (`username`, `remember_login`) and stored in plain text (pre-2014 Chrome).
    pub fn parse(db: &mut SqliteDb, rec: &mut Recorder) {
        let last = db.col_or("cookies", "last_access_utc", "0");
        let value = db.col_or("cookies", "value", "''");
        db.each(&format!("SELECT host_key, name, creation_utc, {last}, {value} FROM cookies"), |r| {
            let host = r.text(0);
            let created = chrome_time(r.int(2));
            super::cookie_identity(rec, &host, &r.text(1), &r.text(4), created);
            rec.emit(created, EventKind::Cookie, host.clone(), format!("cookie {} set", r.text(1)));
            let accessed = chrome_time(r.int(3));
            if accessed.is_some() && accessed != created {
                rec.push_low(accessed, EventKind::Cookie, host, format!("cookie {} last access", r.text(1)));
            }
        });
    }
}
