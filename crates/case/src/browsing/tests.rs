use super::*;
use strata_kernel::Period;
use strata_timeline::{CRYPTO_TAG, EventSource};

const CHROME: &str = "Users/tester/AppData/Local/Google/Chrome/User Data/Default";
const FIREFOX: &str = "home/tester/.mozilla/firefox/abcd1234.default";
const IE_USER: &str = "Documents and Settings/tester";

fn at(y: i64, m: i64, d: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, 12, 0, 0).unwrap()
}

fn ev(t: Timestamp, kind: EventKind, title: &str, artifact: &str, path: &str) -> TimelineEvent {
    TimelineEvent::new(t, kind, title, EventSource::new(artifact, path))
}

/// Two disks: Chrome + Firefox + IE on the first, a second Chrome on the other, plus
/// non-browser events that must never show up.
fn case() -> (tempfile::TempDir, Case, EvidenceId, EvidenceId) {
    let dir = tempfile::tempdir().unwrap();
    let case = Case::open(&dir.path().join("c.strata")).unwrap();
    let mut ids = Vec::new();
    for name in ["a.img", "b.img"] {
        let image = dir.path().join(name);
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        ids.push(case.add_evidence(&image.display().to_string()).unwrap().id);
    }
    let (a, b) = (ids[0], ids[1]);
    let history = format!("{CHROME}/History");
    let mut deleted = ev(at(2012, 3, 4), EventKind::UrlVisited, "https://www.example.com/old", "chrome.history", &history).with_detail("recovered deleted row");
    deleted.set_origin(&history, true);
    let disk_a = vec![
        ev(at(2011, 5, 1), EventKind::UrlVisited, "https://bitcointalk.org/index.php?topic=1", "chrome.history", &history)
            .with_detail("Bitcoin Forum (link)")
            .with_tag(CRYPTO_TAG),
        ev(at(2011, 5, 2), EventKind::UrlVisited, "https://bitcointalk.org/index.php?topic=2", "chrome.history", &history).with_tag(CRYPTO_TAG),
        ev(at(2011, 6, 1), EventKind::UrlVisited, "http://example.com/", "chrome.history", &history).with_detail("Example (typed)"),
        deleted,
        ev(at(2011, 5, 3), EventKind::Search, "how to back up a wallet", "chrome.history", &history),
        ev(at(2011, 5, 4), EventKind::Download, "C:/Users/tester/Downloads/setup.exe", "chrome.history", &history)
            .with_detail("from https://downloads.example.org/setup.exe (42 bytes)"),
        ev(at(2011, 5, 5), EventKind::AccountSeen, "tester @ shop.example.com", "chrome.login_data", &format!("{CHROME}/Login Data")),
        ev(at(2011, 5, 6), EventKind::Cookie, ".example.com", "chrome.cookies", &format!("{CHROME}/Cookies")).with_detail("cookie sid set"),
        ev(at(2011, 5, 7), EventKind::Cookie, ".example.com", "chrome.cookies", &format!("{CHROME}/Cookies")).with_detail("cookie lang last access"),
        ev(at(2011, 5, 8), EventKind::Cookie, ".freebitco.in", "chrome.cookies", &format!("{CHROME}/Cookies")).with_detail("cookie btc set"),
        ev(at(2010, 1, 1), EventKind::UrlVisited, "http://example.net/a", "firefox.places", &format!("{FIREFOX}/places.sqlite")),
        ev(at(2010, 1, 2), EventKind::FormInput, "email = tester@example.com", "firefox.formhistory", &format!("{FIREFOX}/formhistory.sqlite")),
        ev(at(2009, 1, 1), EventKind::UrlVisited, "http://example.org/ie", "ie.index_dat", &format!("{IE_USER}/Local Settings/History/History.IE5/index.dat")),
        ev(at(2009, 1, 2), EventKind::UrlVisited, "http://example.org/typed", "registry.ntuser", &format!("{IE_USER}/NTUSER.DAT")),
        // Not browser history.
        ev(at(2011, 5, 1), EventKind::Search, "wallet", "registry.ntuser", &format!("{IE_USER}/NTUSER.DAT")),
        ev(at(2011, 5, 1), EventKind::FileCreated, "https://example.com/in-a-file-name", "fs.ntfs", "x"),
    ];
    let disk_b = vec![ev(at(2013, 1, 1), EventKind::UrlVisited, "https://example.com/b", "chrome.history", "Users/other/AppData/Local/Google/Chrome/User Data/Profile 1/History")];
    case.store_events(a, &disk_a).unwrap();
    case.store_events(b, &disk_b).unwrap();
    (dir, case, a, b)
}

fn rows(case: &Case, segment: BrowserSegment, filter: BrowserFilter) -> Vec<String> {
    let q = BrowserQuery { filter, segment, limit: 0, offset: 0 };
    let rows = case.browser_rows(&q).unwrap();
    assert_eq!(case.browser_count(&q).unwrap(), rows.len() as u64);
    rows.into_iter().map(|r| r.event.title().to_string()).collect()
}

#[test]
fn segments_hold_only_browser_events() {
    let (_d, case, _, _) = case();
    let history = rows(&case, BrowserSegment::History, BrowserFilter::default());
    assert_eq!(history.len(), 8, "{history:?}");
    assert_eq!(history[0], "http://example.org/ie", "oldest first");
    assert!(history.contains(&"http://example.org/typed".to_string()), "IE typed URLs belong to the browser");
    assert!(!history.iter().any(|t| t.contains("in-a-file-name")));
    assert_eq!(rows(&case, BrowserSegment::Searches, BrowserFilter::default()), ["how to back up a wallet"]);
    assert_eq!(rows(&case, BrowserSegment::Downloads, BrowserFilter::default()).len(), 1);
    assert_eq!(rows(&case, BrowserSegment::Logins, BrowserFilter::default()).len(), 2);
    assert_eq!(rows(&case, BrowserSegment::Cookies, BrowserFilter::default()).len(), 3);
}

#[test]
fn filters_by_disk_profile_period_text_site_and_crypto() {
    let (_d, case, a, b) = case();
    let on = |filter| rows(&case, BrowserSegment::History, filter);
    assert_eq!(on(BrowserFilter { evidence: Some(b), ..Default::default() }), ["https://example.com/b"]);
    let period = Period::parse("2011", "2011").unwrap();
    assert_eq!(on(BrowserFilter::default().within(period)).len(), 3);
    assert_eq!(on(BrowserFilter { text: Some("Example (typed".into()), ..Default::default() }), ["http://example.com/"], "page titles are searched");
    assert_eq!(on(BrowserFilter { crypto_only: true, ..Default::default() }).len(), 2);
    let site = on(BrowserFilter { site: Some("example.com".into()), ..Default::default() });
    assert_eq!(site, ["http://example.com/", "https://www.example.com/old", "https://example.com/b"]);
    assert_eq!(rows(&case, BrowserSegment::Cookies, BrowserFilter { site: Some("www.example.com".into()), ..Default::default() }).len(), 2);

    let firefox = ProfileKey::locate(a, BrowserFamily::Firefox, &format!("{FIREFOX}/places.sqlite"));
    let only = BrowserFilter { profile: Some(firefox), ..Default::default() };
    assert_eq!(on(only.clone()), ["http://example.net/a"]);
    assert_eq!(rows(&case, BrowserSegment::Logins, only), ["email = tester@example.com"]);
    let ie = ProfileKey::locate(a, BrowserFamily::InternetExplorer, &format!("{IE_USER}/NTUSER.DAT"));
    assert_eq!(on(BrowserFilter { profile: Some(ie), ..Default::default() }).len(), 2, "IE profile is the user folder; Chrome under it stays out");
}

#[test]
fn pages_follow_on() {
    let (_d, case, _, _) = case();
    let page = |offset| {
        let q = BrowserQuery { segment: BrowserSegment::History, limit: 3, offset, ..Default::default() };
        case.browser_rows(&q).unwrap().into_iter().map(|r| r.id).collect::<Vec<_>>()
    };
    let (one, two, three) = (page(0), page(3), page(6));
    assert_eq!((one.len(), two.len(), three.len()), (3, 3, 2));
    assert!(one.iter().all(|id| !two.contains(id)));
}

#[test]
fn overview_summarises_profiles_and_sites() {
    let (_d, case, a, b) = case();
    let o = case.browser_overview(&BrowserFilter::default()).unwrap();
    assert_eq!(o.profiles.len(), 4, "{:#?}", o.profiles.iter().map(|p| p.key.label()).collect::<Vec<_>>());
    let chrome = &o.profiles[0];
    assert_eq!((chrome.key.evidence, chrome.key.label().as_str()), (a, "Chrome · tester / Default"));
    assert_eq!(chrome.counts, [4, 1, 1, 1, 3]);
    assert_eq!(chrome.deleted_visits, 1);
    let span = chrome.span.unwrap();
    assert_eq!((span.first, span.last), (at(2011, 5, 1), at(2012, 3, 4)));
    assert_eq!(chrome.top_sites[0], ("bitcointalk.org".to_string(), 2));
    assert_eq!(chrome.top_sites[1], ("example.com".to_string(), 2), "www. folds into the bare host");
    let labels: Vec<String> = o.profiles.iter().map(|p| p.key.label()).collect();
    assert!(labels.contains(&"Internet Explorer · tester".to_string()));
    assert!(labels.contains(&"Firefox · tester / abcd1234.default".to_string()));
    assert_eq!(o.profiles.last().unwrap().key.evidence, b);
    assert_eq!(o.total(BrowserSegment::History), 8);

    assert_eq!(o.sites[0].host, "bitcointalk.org", "crypto sites first");
    assert!(o.sites[0].is_crypto());
    assert_eq!(o.sites[0].service.map(|s| s.id), Some("bitcointalk"));
    let example = o.sites.iter().find(|s| s.host == "example.com").unwrap();
    assert_eq!((example.visits, example.deleted, example.disks.len()), (3, 1, 2));
    assert!(!example.is_crypto());

    let crypto = case.browser_overview(&BrowserFilter { crypto_only: true, ..Default::default() }).unwrap();
    assert!(crypto.sites.iter().all(SiteSummary::is_crypto));
    let in_2009 = case.browser_overview(&BrowserFilter::default().within(Period::parse("2009", "2009").unwrap())).unwrap();
    assert_eq!(in_2009.profiles.len(), 1);
}

#[test]
fn cookies_by_site() {
    let (_d, case, _, _) = case();
    let sites = case.browser_cookie_sites(&BrowserFilter::default()).unwrap();
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].host, "freebitco.in", "catalogued crypto service first");
    assert!(sites[0].is_crypto());
    assert_eq!((sites[1].host.as_str(), sites[1].events), ("example.com", 2));
    assert_eq!(sites[1].names, ["lang", "sid"]);
    assert_eq!(case.browser_cookie_sites(&BrowserFilter { crypto_only: true, ..Default::default() }).unwrap().len(), 1);
}

#[test]
fn profiles_from_paths() {
    let e = EvidenceId::new(1);
    let key = |family, path: &str| ProfileKey::locate(e, family, path);
    assert_eq!(key(BrowserFamily::Chromium, "Documents and Settings/a/Application Data/Opera Software/Opera Stable/History").label(), "Opera · a / Opera Stable");
    assert_eq!(key(BrowserFamily::Chromium, "Users/a/AppData/Local/Yandex/YandexBrowser/User Data/Default/History").browser(), "Yandex");
    assert_eq!(key(BrowserFamily::Firefox, "home/a/.thunderbird/x.default-release/places.sqlite").label(), "Thunderbird · a / x.default-release");
    assert_eq!(key(BrowserFamily::InternetExplorer, "Documents and Settings/a/Cookies/index.dat").dir, "Documents and Settings/a");
    assert_eq!(key(BrowserFamily::Carved, "History").label(), "Unknown (carved) · (unknown folder)");
    let k = key(BrowserFamily::Chromium, "x/Default/History");
    assert!(k.contains("x/Default/Cookies") && !k.contains("x/Default2/History") && !k.contains("x/Default"));
    assert_eq!(BrowserFamily::of("registry.ntuser", "Search"), None);
    assert_eq!(site_key("HTTPS://WWW.Example.COM:8080/x"), "example.com");
    assert_eq!(site_key(".www.example.com"), "example.com");
}
