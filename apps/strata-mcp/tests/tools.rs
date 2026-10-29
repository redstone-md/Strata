//! Every tool against a small synthetic case, called directly (no transport).

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_mcp::StrataServer;
use strata_mcp::tools::chain::{AddressHistoryParams, BalancesParams};
use strata_mcp::tools::files::{FileComplementsParams, FileState, FileTypesParams, FindFilesParams};
use strata_mcp::tools::findings::{Category, GetFindingParams, ListFindingsParams, SharedFindingsParams};
use strata_mcp::tools::insights::{AccountsParams, LeadsParams};
use strata_mcp::tools::overview::{JobsParams, OverviewParams};
use strata_mcp::tools::searches::SearchesParams;
use strata_mcp::tools::timeline::{ActivityParams, HostFactsParams, TimelineParams};
use support::{ADDR, WIF, dump, synthetic_case};

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

fn items(v: &Value) -> &Vec<Value> {
    v["items"].as_array().expect("a page of items")
}

fn files(pattern: &str, state: FileState) -> Parameters<FindFilesParams> {
    Parameters(FindFilesParams { pattern: pattern.into(), disk: None, state, limit: None, offset: 0 })
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_read_the_case_and_leave_it_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let o = json(s.case_overview(Parameters(OverviewParams::default())).await);
    assert_eq!(o["case"], "synthetic");
    assert_eq!(o["disks"].as_array().unwrap().len(), 2);
    assert_eq!(o["findings"]["per_category"]["PrivateKey"], 1, "the 0.1 hex key is below the noise floor");
    assert_eq!(o["balances"]["with_balance"], 1);
    assert_eq!(o["balances"]["total_balance_btc"], "0.05000000");
    assert!(o["leads"].as_u64().unwrap() >= 1);

    let keys = json(s.list_findings(Parameters(ListFindingsParams { categories: vec![Category::PrivateKey], ..Default::default() })).await);
    let key = &items(&keys)[0];
    assert_eq!((items(&keys).len(), key["value"].as_str()), (1, Some(WIF)));
    assert_eq!(key["file"]["state"], "Deleted");
    let all = json(s.list_findings(Parameters(ListFindingsParams { categories: vec![Category::PrivateKey], min_confidence: Some(0.0), ..Default::default() })).await);
    assert_eq!(items(&all).len(), 2);
    let addr = json(s.list_findings(Parameters(ListFindingsParams { text: Some(ADDR.into()), categories: vec![Category::Address], ..Default::default() })).await);
    assert_eq!((items(&addr)[0]["occurrences"].as_u64(), items(&addr)[0]["disks"].as_array().map(Vec::len)), (Some(2), Some(2)));
    let paged = json(s.list_findings(Parameters(ListFindingsParams { limit: Some(1), ..Default::default() })).await);
    assert_eq!((paged["count"].as_u64(), paged["next_offset"].as_u64()), (Some(1), Some(1)));

    let detail = json(s.get_finding(Parameters(GetFindingParams { id: key["id"].as_i64().unwrap() })).await);
    assert_eq!(detail["finding"]["details"]["addresses"]["p2pkh"], ADDR);
    assert_eq!(detail["balances"][0]["address"], ADDR);
    assert_eq!(detail["locations"].as_array().unwrap().len(), 1);
    assert!(s.get_finding(Parameters(GetFindingParams { id: 999_999 })).await.unwrap_err().contains("no finding"));

    let shared = json(s.shared_findings(Parameters(SharedFindingsParams::default())).await);
    assert_eq!(items(&shared)[0]["value"], ADDR);

    let balances = json(s.balances(Parameters(BalancesParams::default())).await);
    assert_eq!(items(&balances)[0]["balance_sat"], 5_000_000);
    let history = json(s.address_history(Parameters(AddressHistoryParams { address: ADDR.into(), limit: None, offset: 0 })).await);
    assert_eq!(history["transactions"]["items"][0]["time"], "2011-06-14 12:00:00");

    let tl = |p: TimelineParams| s.timeline(Parameters(p));
    assert_eq!(items(&json(tl(TimelineParams::default()).await)).len(), 3, "filesystem times are left out");
    assert_eq!(items(&json(tl(TimelineParams { include_filesystem: true, ..Default::default() }).await)).len(), 4);
    let in_2011 = json(tl(TimelineParams { to: Some("2011".into()), ..Default::default() }).await);
    assert_eq!(items(&in_2011).len(), 2);
    assert_eq!(items(&json(tl(TimelineParams { from: Some("2012-02".into()), text: Some("mtgox".into()), ..Default::default() }).await)).len(), 1);
    assert!(tl(TimelineParams { from: Some("last spring".into()), ..Default::default() }).await.is_err());
    let days = json(s.activity_per_day(Parameters(ActivityParams::default())).await);
    assert_eq!(items(&days)[0]["day"], "2011-06-14");
    assert_eq!(json(s.host_facts(Parameters(HostFactsParams::default())).await), Value::Array(vec![]));

    let accounts = json(s.accounts(Parameters(AccountsParams { text: Some("gox".into()), ..Default::default() })).await);
    assert_eq!(items(&accounts)[0]["identifier"], "gox_tester");
    let leads = json(s.leads(Parameters(LeadsParams { resolve: true, ..Default::default() })).await);
    let lead = items(&leads).iter().find(|l| l["finding_ids"].as_array().is_some_and(|f| !f.is_empty())).expect("a lead on the key");
    assert!(!lead["explanation"].as_array().unwrap().is_empty());
    assert!(!lead["findings"].as_array().unwrap().is_empty());

    let wallets = json(s.find_files(files("WALLET", FileState::Any)).await);
    assert_eq!((items(&wallets).len(), items(&wallets)[0]["state"].as_str()), (1, Some("Deleted")));
    let photos = json(s.find_files(files("*.jpg", FileState::Live)).await);
    assert_eq!(items(&photos)[0]["renamed"], true);
    assert!(items(&json(s.find_files(files("*.txt", FileState::Deleted)).await)).is_empty());
    let types = json(s.file_types(Parameters(FileTypesParams::default())).await);
    assert_eq!(types["types"].as_array().unwrap().len(), 2);
    assert_eq!(types["renamed_files"]["items"][0]["name"], "photo.jpg");
    assert!(items(&json(s.file_complements(Parameters(FileComplementsParams::default())).await)).is_empty());

    let searches = json(s.searches(Parameters(SearchesParams::default())).await);
    let id = items(&searches)[0]["id"].as_i64().unwrap();
    let matches = json(s.searches(Parameters(SearchesParams { search_id: Some(id), ..Default::default() })).await);
    assert_eq!(matches["matches"]["items"][0]["text"], "bitcoin");
    assert_eq!(matches["search"]["state"], "done");

    assert_eq!(json(s.jobs(Parameters(JobsParams::default())).await), Value::Array(vec![]));

    drop(s);
    assert_eq!(before, dump(&root), "the server changed the case");
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_folder_that_is_not_a_case() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nothing.strata");
    assert!(StrataServer::open(&missing).is_err());
    assert!(!missing.exists(), "no case is created");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_case_answers_with_empty_lists() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("empty.strata");
    drop(strata_workbench::Workbench::open_idle(&root).unwrap());
    let s = StrataServer::open(&root).unwrap();
    assert!(items(&json(s.searches(Parameters(SearchesParams::default())).await)).is_empty());
    assert!(items(&json(s.list_findings(Parameters(ListFindingsParams::default())).await)).is_empty());
    assert!(items(&json(s.leads(Parameters(LeadsParams::default())).await)).is_empty());
}
