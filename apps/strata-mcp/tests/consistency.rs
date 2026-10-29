//! The consistency tool against the synthetic case: its blank images have no partitions, which
//! the tool must say loudly, plus a cleaning program recorded on the laptop. All values are made up.

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_mcp::StrataServer;
use strata_mcp::tools::consistency::ConsistencyParams;
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_workbench::Workbench;
use support::{at, dump, synthetic_case};

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn consistency_per_disk() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    {
        let wb = Workbench::open_idle(&root).unwrap();
        let laptop = wb.evidence().unwrap()[0].id;
        let run = TimelineEvent::new(at(2012, 3, 1), EventKind::ProgramRun, r"C:\Program Files\CCleaner\CCleaner.exe", EventSource::new("windows.prefetch", "Windows/Prefetch"));
        wb.case().write(|w| w.volume_events(laptop, 0, &[run])).unwrap();
    }
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let all = json(s.consistency(Parameters(ConsistencyParams::default())).await);
    let disks = all.as_array().unwrap();
    assert_eq!(disks.len(), 2);
    let laptop = &disks[0];
    assert_eq!(laptop["verdict"], "Unreadable");
    assert_eq!(laptop["headline"], "Strata could not read the file system");
    let first = &laptop["observations"][0];
    assert_eq!((first["severity"].as_str(), first["signal"].as_str()), (Some("alert"), Some("unknown_file_system")));
    assert!(first["figures"][0][0] == "Disk size");
    let cc = laptop["observations"].as_array().unwrap().iter().find(|o| o["signal"] == "cleaning_tool").expect("CCleaner run");
    assert_eq!(cc["title"], "CCleaner run");

    let one = json(s.consistency(Parameters(ConsistencyParams { disk: Some(laptop["disk"].as_u64().unwrap() as u32), skip_info: true })).await);
    assert_eq!(one.as_array().unwrap().len(), 1);
    assert!(one[0]["observations"].as_array().unwrap().iter().all(|o| o["severity"] != "info"));
    assert!(s.consistency(Parameters(ConsistencyParams { disk: Some(99), skip_info: false })).await.unwrap_err().contains("no disk 99"));

    drop(s);
    assert_eq!(dump(&root), before, "the consistency tool leaves the case unchanged");
}
