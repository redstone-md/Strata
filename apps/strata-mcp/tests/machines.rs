//! Machine tools against the synthetic case plus host facts and activity of one Windows XP
//! installation on its second disk. All values are made up.

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_case::HostFact;
use strata_mcp::StrataServer;
use strata_mcp::tools::machines::{MachinesParams, UsageParams};
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_workbench::Workbench;
use support::{at, dump, synthetic_case};

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn machines_and_usage_periods() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    {
        let wb = Workbench::open_idle(&root).unwrap();
        let disk = wb.evidence().unwrap()[1].id;
        let fact = |key: &str, value: &str, source: &str| HostFact {
            evidence: disk,
            volume: Some(0),
            key: key.into(),
            value: value.into(),
            artifact: "registry.system".into(),
            source: source.into(),
        };
        let facts = [
            fact("computer_name", "OLGA-XP", "WINDOWS/system32/config/SYSTEM"),
            fact("computer_name", "OLGA-XP", "WINDOWS/repair/system"),
            fact("windows_product", "Microsoft Windows XP", "WINDOWS/system32/config/software"),
            fact("timezone", "Russian Standard Time", "WINDOWS/system32/config/SYSTEM"),
            fact("timezone_bias", "-180", "WINDOWS/system32/config/SYSTEM"),
            fact("user", r#"{"name":"Olga","logon_count":12}"#, "WINDOWS/system32/config/SAM"),
        ];
        let history = "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat";
        let events: Vec<TimelineEvent> = (10..=14)
            .map(|d| TimelineEvent::new(at(2011, 3, d), EventKind::UrlVisited, "http://example.com/", EventSource::new("ie.index_dat", history)))
            .chain([TimelineEvent::new(at(2011, 3, 14), EventKind::Login, "Windows logon: Olga", EventSource::new("registry.sam", "WINDOWS/system32/config/SAM"))])
            .collect();
        wb.case()
            .write(|w| {
                w.facts(&facts)?;
                w.volume_events(disk, 0, &events)
            })
            .unwrap();
    }
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let all = json(s.machines(Parameters(MachinesParams::default())).await);
    let disks = all.as_array().unwrap();
    assert_eq!(disks.len(), 2);
    assert!(disks[0]["machines"].as_array().unwrap().iter().all(|m| m["profile"]["computer_name"].is_null()), "the laptop has no host facts");
    let m = &disks[1]["machines"][0];
    assert_eq!(m["profile"]["computer_name"]["value"], "OLGA-XP");
    assert_eq!(m["profile"]["computer_name"]["source"], "WINDOWS/system32/config/SYSTEM");
    assert_eq!(m["profile"]["os"], "Microsoft Windows XP");
    assert_eq!(m["profile"]["time_zone"], "Russian Standard Time (UTC+03:00)");
    let users = m["profile"]["users"].as_array().unwrap();
    let olga = users.iter().find(|u| u["name"] == "Olga").expect("the SAM user");
    assert_eq!(olga["logon_count"], 12);
    assert_eq!(m["usage"]["first_day"], "2011-03-10");
    assert_eq!(m["usage"]["last_active_day"], "2011-03-14");
    assert_eq!(m["usage"]["clock"], "UTC+03:00");

    let one = json(s.usage_periods(Parameters(UsageParams { disk: Some(disks[1]["disk"].as_u64().unwrap() as u32), months: true })).await);
    let usage = &one[0]["usage"];
    assert_eq!(usage["active_days"], 5);
    assert_eq!(usage["periods"][0]["activity"][0], serde_json::json!(["web", 5]));
    assert_eq!(usage["months"], serde_json::json!([["2011-03", 5]]));
    assert_eq!(one[0]["machines"][0]["machine"], "OLGA-XP");
    assert!(s.usage_periods(Parameters(UsageParams { disk: Some(99), months: false })).await.unwrap_err().contains("no disk 99"));

    drop(s);
    assert_eq!(dump(&root), before, "the machine tools leave the case unchanged");
}
