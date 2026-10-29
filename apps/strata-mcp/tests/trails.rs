//! `wallet_trails` on the synthetic case: the deleted wallet.dat whose key was still read.

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_mcp::StrataServer;
use strata_mcp::tools::trails::{FateFilter, WalletTrailsParams};
use support::{dump, synthetic_case};

fn trails(reply: Result<String, String>) -> Vec<Value> {
    let v: Value = serde_json::from_str(&reply.expect("tool succeeds")).expect("JSON");
    v["items"].as_array().expect("a page").clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_trails_show_the_fate_and_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let all = trails(s.wallet_trails(Parameters(WalletTrailsParams::default())).await);
    let wallet = all.iter().find(|t| t["name"] == "wallet.dat").expect("wallet.dat trail");
    assert_eq!(wallet["fate"], "deleted, recoverable", "{wallet}");
    let steps = wallet["steps"].as_array().unwrap();
    assert!(steps.iter().any(|s| s["finding_id"].is_number()), "the key read from it: {steps:?}");
    assert!(steps.iter().any(|s| s["file"].is_string()), "the file entry: {steps:?}");

    let deleted = trails(s.wallet_trails(Parameters(WalletTrailsParams { fate: Some(FateFilter::Deleted), ..Default::default() })).await);
    assert_eq!(deleted.len(), all.iter().filter(|t| t["fate"].as_str().unwrap().starts_with("deleted")).count());
    let none = trails(s.wallet_trails(Parameters(WalletTrailsParams { to: Some("2005".into()), ..Default::default() })).await);
    assert!(none.iter().all(|t| t["name"] != "wallet.dat"), "outside the period");
    assert!(s.wallet_trails(Parameters(WalletTrailsParams { from: Some("soon".into()), ..Default::default() })).await.is_err());
    drop(s);
    assert_eq!(dump(&root), before, "read-only");
}
