//! End to end: the real binary over stdio JSON-RPC, as an MCP client would drive it.

mod support;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(30);

#[test]
fn initialize_list_and_call_over_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let root = support::synthetic_case(dir.path());
    let before = support::dump(&root);
    let mut child = Command::new(env!("CARGO_BIN_EXE_strata-mcp"))
        .arg("--case")
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel::<Value>();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str(&line) else { continue };
            if tx.send(v).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    let mut send = |v: Value| writeln!(stdin, "{v}").and_then(|_| stdin.flush()).unwrap();
    let reply = |id: u64| loop {
        let v = rx.recv_timeout(WAIT).expect("a reply in time");
        if v["id"] == id {
            break v;
        }
    };

    send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}}));
    let init = reply(1);
    assert_eq!(init["result"]["serverInfo"]["name"], "strata");
    assert!(init["result"]["instructions"].as_str().unwrap().contains("read-only"));
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = reply(2);
    let list = tools["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = list.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(list.iter().all(|t| t["annotations"]["readOnlyHint"] == true), "every tool is marked read-only");
    for name in ["case_overview", "list_findings", "get_finding", "timeline", "leads", "find_files", "searches", "jobs"] {
        assert!(names.contains(&name), "{name} missing from {names:?}");
    }

    send(json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "list_findings", "arguments": {"categories": ["PrivateKey"]}}}));
    let call = reply(3);
    assert_ne!(call["result"]["isError"], true, "{call}");
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    let page: Value = serde_json::from_str(text).unwrap();
    assert_eq!(page["items"][0]["value"], support::WIF);

    send(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "case_overview"}}));
    let overview = reply(4);
    assert!(overview["result"]["content"][0]["text"].as_str().unwrap().contains("\"case\":\"synthetic\""), "{overview}");

    drop(send);
    drop(stdin);
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(started.elapsed() < WAIT, "the server exits when stdin closes");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(before, support::dump(&root), "the server changed the case");
}
