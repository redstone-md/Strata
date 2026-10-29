//! The connection map tool against the synthetic case: the overview, an ego network with the
//! evidence of every link of its centre, filters, and refusals.

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_mcp::StrataServer;
use strata_mcp::tools::graph::ConnectionsParams;
use support::{ADDR, WIF, dump, synthetic_case};

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

fn keys(v: &Value) -> Vec<&str> {
    v["nodes"].as_array().unwrap().iter().filter_map(|n| n["key"].as_str()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn maps_connections_and_explains_them() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let overview = json(s.connections(Parameters(ConnectionsParams::default())).await);
    assert_eq!(overview["mode"], "overview");
    let address = format!("addr:{ADDR}");
    assert!(keys(&overview).contains(&address.as_str()));
    let funded = overview["nodes"].as_array().unwrap().iter().find(|n| n["key"] == address.as_str()).unwrap();
    assert_eq!(funded["balance_btc"], "0.05000000");
    assert!(funded["flags"].as_array().unwrap().iter().any(|f| f == "funded"));
    assert!(funded["flags"].as_array().unwrap().iter().any(|f| f == "cross_disk"));

    let around = json(s.connections(Parameters(ConnectionsParams { around: Some(ADDR.into()), ..Default::default() })).await);
    assert_eq!((around["mode"].as_str(), around["centre"].as_str()), (Some("around"), Some(address.as_str())));
    let links = around["centre_links"].as_array().unwrap();
    let derived = links.iter().find(|l| l["reason"] == "derived from").expect("the key derives the address");
    assert_eq!(derived["to"], format!("key:{WIF}"));
    assert!(derived["evidence"][0]["finding_id"].as_i64().is_some());
    assert!(around["edges"].as_array().unwrap().iter().all(|e| keys(&around).contains(&e["from"].as_str().unwrap())));

    let secrets = json(s.connections(Parameters(ConnectionsParams { around: Some(ADDR.into()), kinds: vec!["secret".into()], ..Default::default() })).await);
    assert!(secrets["nodes"].as_array().unwrap().iter().skip(1).all(|n| n["kind"] == "secret"));
    let small = json(s.connections(Parameters(ConnectionsParams { limit: Some(2), ..Default::default() })).await);
    assert!(small["nodes"].as_array().unwrap().len() <= 2);

    let unknown = s.connections(Parameters(ConnectionsParams { around: Some("nobody@example.invalid".into()), ..Default::default() })).await;
    assert!(unknown.unwrap_err().contains("nothing in the connection map"));
    assert!(s.connections(Parameters(ConnectionsParams { kinds: vec!["planet".into()], ..Default::default() })).await.unwrap_err().contains("unknown kind"));

    drop(s);
    assert_eq!(dump(&root), before, "the map is read-only");
}
