//! The browser_history tool against the synthetic case (two visits and a saved login on the
//! laptop, read by `chrome.history`).

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_mcp::StrataServer;
use strata_mcp::tools::browser::BrowserHistoryParams;
use support::{dump, synthetic_case};

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

fn view(name: &str) -> BrowserHistoryParams {
    BrowserHistoryParams { view: Some(name.into()), ..Default::default() }
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_history_views() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let profiles = json(s.browser_history(Parameters(view("profiles"))).await);
    let p = &profiles["items"][0];
    assert_eq!((p["visits"].as_u64(), p["logins_and_forms"].as_u64(), p["folder"].as_str()), (Some(2), Some(1), Some("Users/a/AppData")));
    assert_eq!(p["user"], "a");

    let sites = json(s.browser_history(Parameters(view("sites"))).await);
    let hosts: Vec<&str> = sites["items"].as_array().unwrap().iter().map(|s| s["host"].as_str().unwrap()).collect();
    assert_eq!(hosts.len(), 2);
    assert!(sites["items"].as_array().unwrap().iter().all(|s| s["crypto"] == true && s["known"]["service"].is_string()));

    let history = json(s.browser_history(Parameters(BrowserHistoryParams { limit: Some(1), ..Default::default() })).await);
    assert_eq!((history["total"].as_u64(), history["next_offset"].as_u64()), (Some(2), Some(1)));
    assert_eq!(history["items"][0]["title"], "http://freebitcoins.appspot.com/");
    let later = json(s.browser_history(Parameters(BrowserHistoryParams { from: Some("2012".into()), ..Default::default() })).await);
    assert_eq!(later["items"][0]["title"], "https://mtgox.com/trade");
    let on_site = json(s.browser_history(Parameters(BrowserHistoryParams { site: Some("mtgox.com".into()), ..Default::default() })).await);
    assert_eq!(on_site["total"], 1);

    let logins = json(s.browser_history(Parameters(view("logins"))).await);
    assert_eq!(logins["items"][0]["title"], "gox_tester @ mtgox.com");
    let narrowed = BrowserHistoryParams { disk: Some(1), profile: Some("Users/a/AppData".into()), ..view("history") };
    assert_eq!(json(s.browser_history(Parameters(narrowed)).await)["total"], 2);

    assert!(s.browser_history(Parameters(view("bookmarks"))).await.unwrap_err().contains("unknown view"));
    assert!(s.browser_history(Parameters(BrowserHistoryParams { profile: Some("x".into()), ..Default::default() })).await.is_err());
    drop(s);
    assert_eq!(dump(&root), before, "reading browser history leaves the case unchanged");
}
