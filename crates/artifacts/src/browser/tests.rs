use super::*;
use crate::results::IdentityKind;
use crate::sqlite::testutil::db_bytes;

/// 2011-05-14 17:36:09 UTC as WebKit µs and PRTime µs.
const UNIX: i64 = 1_305_394_569;
const WEBKIT: i64 = (UNIX + 11_644_473_600) * 1_000_000;
const PRTIME: i64 = UNIX * 1_000_000;

fn chrome_history_sql() -> String {
    format!(
        "PRAGMA page_size=1024; PRAGMA secure_delete=OFF;
         CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER,
            typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
         CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
            transition INTEGER, segment_id INTEGER);
         CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, lower_term LONGVARCHAR, term LONGVARCHAR);
         CREATE TABLE downloads(id INTEGER PRIMARY KEY, full_path LONGVARCHAR, url LONGVARCHAR, start_time INTEGER,
            received_bytes INTEGER, total_bytes INTEGER, state INTEGER, end_time INTEGER, opened INTEGER);
         INSERT INTO urls VALUES(1,'https://bitcointalk.org/index.php?topic=1','Bitcoin Forum',2,0,{WEBKIT},0);
         INSERT INTO urls VALUES(2,'http://e.mail.ru/messages/inbox','Inbox',1,1,{WEBKIT},0);
         INSERT INTO urls VALUES(3,'http://www.google.ru/search?q=electrum','electrum - Google',1,0,{WEBKIT},0);
         INSERT INTO visits VALUES(1,1,{WEBKIT},0,1,0);
         INSERT INTO visits VALUES(2,1,{w2},0,0,0);
         INSERT INTO keyword_search_terms VALUES(2,3,'electrum','electrum');
         INSERT INTO downloads VALUES(1,'C:\\bitcoin-0.3.21-win32-setup.exe','http://bitcoin.org/x.exe',{UNIX},1,9,1,0,0);",
        w2 = WEBKIT + 60_000_000
    )
}

#[test]
fn chrome_history() {
    let out = parse_sqlite("History", &db_bytes(&chrome_history_sql()));
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    let visits: Vec<_> = out.events.iter().filter(|e| e.kind() == EventKind::UrlVisited).collect();
    // 2 visits of url 1, plus urls 2 and 3 via last_visit_time.
    assert_eq!(visits.len(), 4);
    assert_eq!(visits[0].at().to_string(), "2011-05-14 17:36:09");
    assert!(visits[0].detail().contains("typed"));
    let search = out.events.iter().find(|e| e.kind() == EventKind::Search).unwrap();
    assert_eq!(search.title(), "electrum");
    let dl = out.events.iter().find(|e| e.kind() == EventKind::Download).unwrap();
    assert_eq!(dl.at().to_string(), "2011-05-14 17:36:09");
    assert!(dl.detail().contains("bitcoin.org"));
}

#[test]
fn chrome_history_deleted_rows_recovered() {
    let mut sql = chrome_history_sql();
    for i in 0..60 {
        sql.push_str(&format!(
            "INSERT INTO urls VALUES({},'https://mtgox.com/trade/{i}?{}','Mt.Gox',1,0,{WEBKIT},0);",
            100 + i,
            "p".repeat(30)
        ));
    }
    sql.push_str("DELETE FROM urls WHERE id >= 100;");
    let out = parse_sqlite("History", &db_bytes(&sql));
    let recovered: Vec<_> = out.events.iter().filter(|e| e.has_tag("recovered")).collect();
    assert!(!recovered.is_empty(), "no deleted rows recovered");
    assert!(recovered.iter().all(|e| e.source().deleted && e.title().starts_with("https://mtgox.com/trade/")));
    assert!(recovered.iter().any(|e| e.at().to_string() == "2011-05-14 17:36:09"));
}

#[test]
fn damaged_history_falls_back_to_raw() {
    let mut bytes = db_bytes(&chrome_history_sql());
    // Destroy the schema page header, keep the data pages.
    for b in &mut bytes[100..400] {
        *b = 0xEE;
    }
    let out = parse_sqlite("History", &bytes);
    assert!(!out.damage.is_empty());
    assert!(out.events.iter().any(|e| e.title() == "https://bitcointalk.org/index.php?topic=1" && e.has_tag("raw")));
}

#[test]
fn chrome_login_data_and_web_data() {
    let login = db_bytes(&format!(
        "CREATE TABLE logins(origin_url VARCHAR, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR,
            password_element VARCHAR, password_value BLOB, signon_realm VARCHAR, date_created INTEGER);
         INSERT INTO logins VALUES('http://e.mail.ru/','','Login','anna.test3','Password',x'01000000D08C9DDF0115D1118C7A00C04FC297EB','http://e.mail.ru/',{UNIX});
         INSERT INTO logins VALUES('http://vk.com/','','email','ivan.test2@mail.ru','pass',x'','http://vk.com/',{WEBKIT});"
    ));
    let out = parse_sqlite("Login Data", &login);
    assert_eq!(out.events.len(), 2);
    assert!(out.events[0].detail().contains("DPAPI-encrypted blob, 20 bytes"));
    assert_eq!(out.events[0].at().to_string(), "2011-05-14 17:36:09");
    assert!(out.identities.iter().any(|i| i.value == "anna.test3" && i.kind == IdentityKind::Login));
    assert!(out.identities.iter().any(|i| i.value == "ivan.test2@mail.ru" && i.kind == IdentityKind::Email));

    let web = db_bytes(&format!(
        "CREATE TABLE autofill(name VARCHAR, value VARCHAR, value_lower VARCHAR, pair_id INTEGER PRIMARY KEY, count INTEGER);
         CREATE TABLE autofill_dates(pair_id INTEGER, date_created INTEGER);
         CREATE TABLE autofill_profile_emails(guid VARCHAR, email VARCHAR);
         INSERT INTO autofill VALUES('UserRegistrationPortletFormEmail','olga.test1@mail.ru','olga.test1@mail.ru',1,2);
         INSERT INTO autofill VALUES('login','petr.test4','petr.test4',2,5);
         INSERT INTO autofill_dates VALUES(1,{UNIX});
         INSERT INTO autofill_dates VALUES(2,{UNIX});
         INSERT INTO autofill_profile_emails VALUES('g','anna.test3@mail.ru');"
    ));
    let out = parse_sqlite("Web Data", &web);
    assert_eq!(out.events.iter().filter(|e| e.kind() == EventKind::FormInput).count(), 2);
    for v in ["olga.test1@mail.ru", "petr.test4", "anna.test3@mail.ru"] {
        assert!(out.identities.iter().any(|i| i.value == v), "{v}");
    }
}

#[test]
fn chrome_cookies() {
    let bytes = db_bytes(&format!(
        "CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT,
            expires_utc INTEGER, secure INTEGER, httponly INTEGER, last_access_utc INTEGER);
         INSERT INTO cookies VALUES({WEBKIT},'.wmtransfer.com','sid','secret','/',0,0,0,{w2});",
        w2 = WEBKIT + 3_600_000_000
    ));
    let out = parse_sqlite("Cookies", &bytes);
    assert_eq!(out.events.len(), 2);
    assert!(out.events.iter().all(|e| !e.detail().contains("secret")));
}

#[test]
fn firefox_places_forms_cookies() {
    let places = db_bytes(&format!(
        "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR,
            visit_count INTEGER, hidden INTEGER, typed INTEGER, favicon_id INTEGER, frecency INTEGER, last_visit_date INTEGER);
         CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER,
            visit_type INTEGER, session INTEGER);
         CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, position INTEGER,
            title LONGVARCHAR, keyword_id INTEGER, folder_type TEXT, dateAdded INTEGER, lastModified INTEGER);
         INSERT INTO moz_places VALUES(1,'https://www.torproject.org/','Tor','',1,0,0,0,0,{PRTIME});
         INSERT INTO moz_places VALUES(2,'http://blockchain.info/wallet','Wallet','',0,0,0,0,0,{PRTIME});
         INSERT INTO moz_historyvisits VALUES(1,0,1,{PRTIME},1,0);
         INSERT INTO moz_bookmarks VALUES(1,1,2,0,0,'My wallet',0,NULL,{PRTIME},{PRTIME});"
    ));
    let out = parse_sqlite("places.sqlite", &places);
    assert_eq!(out.events.len(), 3, "{:?}", out.events);
    assert!(out.events.iter().all(|e| e.at().to_string() == "2011-05-14 17:36:09"));

    let forms = db_bytes(&format!(
        "CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER,
            firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
         INSERT INTO moz_formhistory VALUES(1,'email','anna.test3@mail.ru',3,{PRTIME},{PRTIME},'g');
         INSERT INTO moz_formhistory VALUES(2,'searchbar-history','биткоин',1,{PRTIME},{PRTIME},'h');"
    ));
    let out = parse_sqlite("formhistory.sqlite", &forms);
    assert!(out.events.iter().any(|e| e.kind() == EventKind::Search && e.title() == "биткоин"));
    assert_eq!(out.identities.len(), 1);

    let cookies = db_bytes(&format!(
        "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
            lastAccessed INTEGER, creationTime INTEGER);
         INSERT INTO moz_cookies VALUES(1,'sid','v','.mtgox.com','/',0,{PRTIME},{PRTIME});"
    ));
    assert_eq!(parse_sqlite("cookies.sqlite", &cookies).events.len(), 1);
}

#[test]
fn firefox_logins_json() {
    let json = format!(
        r#"{{"nextId":2,"logins":[{{"id":1,"hostname":"https://bitcointalk.org","encryptedUsername":"MDIE...","encryptedPassword":"MDIE...","timeCreated":{ms},"timeLastUsed":{ms}}}]}}"#,
        ms = UNIX * 1000
    );
    let mut rec = Recorder::new("firefox.logins");
    FirefoxLogins::parse_json(json.as_bytes(), &mut rec);
    let out = rec.finish();
    assert_eq!(out.events.len(), 2);
    assert!(out.events[0].detail().contains("encrypted username present"));
    let mut rec = Recorder::new("firefox.logins");
    FirefoxLogins::parse_json(b"{not json", &mut rec);
    assert_eq!(rec.finish().damage.len(), 1);
}

#[test]
fn truncated_and_garbage_never_panic() {
    let bytes = db_bytes(&chrome_history_sql());
    for cut in [0, 15, 16, 100, 512, 1024, 1500, 2048, bytes.len() / 2, bytes.len() - 1] {
        let _ = parse_sqlite("History", &bytes[..cut.min(bytes.len())]);
    }
    let junk: Vec<u8> = (0..20_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let _ = parse_sqlite("places.sqlite", &junk);
    let mut fake = crate::sqlite::MAGIC.to_vec();
    fake.extend_from_slice(&junk);
    let _ = parse_sqlite("History", &fake);
}

