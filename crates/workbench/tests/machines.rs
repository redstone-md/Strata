//! Machine profiles and usage read back from a case: two Windows installations on two volumes,
//! facts and events stored as the Artifacts step stores them. All values are made up.

use strata_case::{EventFilter, HostFact};
use strata_kernel::Timestamp;
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_workbench::{ActivityKind, Workbench};

fn at(y: i64, m: i64, d: i64, h: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, h, 0, 0).unwrap()
}

fn event(t: Timestamp, kind: EventKind, title: &str, artifact: &str, path: &str) -> TimelineEvent {
    TimelineEvent::new(t, kind, title, EventSource::new(artifact, path))
}

#[test]
fn machines_and_usage_from_stored_facts_and_events() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    std::fs::write(&image, vec![0u8; 1 << 16]).unwrap();
    let wb = Workbench::open_idle(&dir.path().join("m.strata")).unwrap();
    let id = wb.add_evidence(&image.display().to_string()).unwrap().id;
    let fact = |volume: u32, key: &str, value: &str, source: &str| HostFact {
        evidence: id,
        volume: Some(volume),
        key: key.into(),
        value: value.into(),
        artifact: "registry.system".into(),
        source: source.into(),
    };
    let facts = [
        fact(0, "computer_name", "OLGA-XP", "WINDOWS/system32/config/SYSTEM"),
        fact(0, "windows_product", "Microsoft Windows XP", "WINDOWS/system32/config/software"),
        fact(0, "url", "http://example.com/", "Documents and Settings/Olga/index.dat"),
        fact(1, "computer_name", "OLGA-PC", "Windows/System32/config/SYSTEM"),
        fact(1, "timezone_bias", "-180", "Windows/System32/config/SYSTEM"),
    ];
    let xp_history = "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat";
    let xp_events = [
        event(at(2009, 5, 1, 18), EventKind::UrlVisited, "http://bitcoin.org/", "ie.index_dat", xp_history),
        event(at(2009, 5, 2, 18), EventKind::UrlVisited, "http://example.com/", "ie.index_dat", xp_history),
        event(at(2009, 5, 2, 19), EventKind::ProgramInstalled, "Electrum", "registry.software", "WINDOWS/system32/config/software"),
        event(at(2009, 5, 3, 9), EventKind::FileModified, "C:\\x.txt", "fs.ntfs", "x.txt"),
        event(at(2090, 1, 1, 9), EventKind::UrlVisited, "http://future.example/", "ie.index_dat", xp_history),
    ];
    let w7_events = [
        event(at(2012, 3, 1, 20), EventKind::SystemLog, "System start (event log service started)", "windows.evtx", "Windows/System32/winevt/Logs/System.evtx"),
        event(at(2012, 3, 1, 20), EventKind::SystemLog, "Service Control Manager event 7036", "windows.evtx", "Windows/System32/winevt/Logs/System.evtx"),
        event(at(2012, 3, 1, 21), EventKind::Login, "Logon: OLGA-PC\\Olga (type 2, interactive)", "windows.evtx", "Windows/System32/winevt/Logs/Security.evtx"),
        event(at(2012, 3, 2, 21), EventKind::Login, "Failed logon: OLGA-PC\\Olga (type 2, interactive)", "windows.evtx", "Windows/System32/winevt/Logs/Security.evtx"),
    ];
    wb.case()
        .write(|w| {
            w.facts(&facts)?;
            w.volume_events(id, 0, &xp_events)?;
            w.volume_events(id, 1, &w7_events)
        })
        .unwrap();

    let disk = wb.machines(id).unwrap();
    let labels: Vec<String> = disk.machines.iter().map(|m| m.profile.label()).collect();
    assert_eq!(labels, ["OLGA-XP", "OLGA-PC"], "volume order, both systems");
    let xp = &disk.machines[0];
    assert_eq!(xp.usage.range_label().as_deref(), Some("2009-05-01 – 2009-05-02"), "installs, file times and 2090 do not count");
    assert_eq!(xp.usage.out_of_range, 1);
    assert_eq!(xp.profile.software.first().map(|s| s.name.as_str()), Some("Electrum"));
    let w7 = &disk.machines[1];
    assert_eq!((w7.usage.events, w7.usage.clock.as_str()), (2, "UTC+03:00"), "start-up and the logon, not the service event or the failure");
    assert_eq!(w7.usage.periods[0].kinds.iter().map(|k| k.kind).collect::<Vec<_>>().len(), 2);
    assert!(w7.usage.periods[0].kinds.iter().any(|k| k.kind == ActivityKind::Power));
    assert_eq!(w7.profile.users.first().map(|u| u.name.as_str()), Some("Olga"));
    // The short XP period stays: it is a machine's own use, not a stray. Days are UTC+3 local.
    assert_eq!(disk.usage.range_label().as_deref(), Some("2009-05-01 – 2012-03-02"));
    assert_eq!(wb.disk_usage(id).unwrap().active_days, 4);

    let groups = wb.fact_groups(id, 10).unwrap();
    let names = groups.iter().find(|g| g.key == "computer_name").unwrap();
    assert_eq!((names.total, names.distinct), (2, 2));
    // The raw query helpers stay generic.
    assert!(wb.case().hourly_events(id, &EventFilter::default()).unwrap().is_empty());
}
