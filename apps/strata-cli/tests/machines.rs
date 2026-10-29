//! `machines` and `usage` on a small synthetic case, through the real binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use strata_kernel::Timestamp;
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_workbench::{HostFact, Workbench};

fn case(dir: &Path) -> PathBuf {
    let root = dir.join("cli.strata");
    let image = dir.join("disk.img");
    std::fs::write(&image, vec![0u8; 1 << 16]).unwrap();
    let wb = Workbench::open_idle(&root).unwrap();
    let id = wb.add_evidence(&image.display().to_string()).unwrap().id;
    let fact = |key: &str, value: &str| HostFact {
        evidence: id,
        volume: Some(0),
        key: key.into(),
        value: value.into(),
        artifact: "registry.system".into(),
        source: "WINDOWS/system32/config/SYSTEM".into(),
    };
    let at = |d: i64| Timestamp::from_civil(2011, 3, d, 19, 0, 0).unwrap();
    let path = "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat";
    let events: Vec<TimelineEvent> =
        (1..=5).map(|d| TimelineEvent::new(at(d), EventKind::UrlVisited, "http://example.com/", EventSource::new("ie.index_dat", path))).collect();
    wb.case()
        .write(|w| {
            w.facts(&[fact("computer_name", "OLGA-XP"), fact("windows_product", "Microsoft Windows XP"), fact("timezone_bias", "-180")])?;
            w.volume_events(id, 0, &events)
        })
        .unwrap();
    root
}

fn cli(root: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_strata-cli")).arg("-c").arg(root).args(args).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn machines_and_usage_commands() {
    let dir = tempfile::tempdir().unwrap();
    let root = case(dir.path());
    let text = cli(&root, &["machines"]);
    assert!(text.contains("OLGA-XP  System on volume 0"), "{text}");
    assert!(text.contains("Microsoft Windows XP"), "{text}");
    assert!(text.contains("in use 2011-03-01 – 2011-03-05 (UTC+03:00)"), "{text}");
    let json: serde_json::Value = serde_json::from_str(cli(&root, &["machines", "--json"]).trim()).unwrap();
    assert_eq!(json["machines"][0]["profile"]["computer_name"][0]["value"], "OLGA-XP");
    assert_eq!(json["usage"]["active_days"], 5);
    let usage = cli(&root, &["usage", "--disk", "1"]);
    assert!(usage.contains("2011-03-01 – 2011-03-05  5 active days, 5 events: web 5"), "{usage}");
    let missing = Command::new(env!("CARGO_BIN_EXE_strata-cli")).arg("-c").arg(&root).args(["usage", "--disk", "9"]).output().unwrap();
    assert!(!missing.status.success());
}
