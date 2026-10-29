//! A synthetic disk holding Windows XP on volume 1, Windows 7 on volume 2 (with the XP it
//! replaced in `Windows.old`), Ubuntu on volume 3 with `/home` on volume 4, and a Docker
//! container. Linux facts come from the real parsers; Windows facts as the hive parsers store
//! them. All names are made up.

use super::*;
use strata_artifacts::host::{NetworkProfileRecord, UsbRecord, UserRecord, keys, to_value};
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

fn t(y: i64, m: i64, d: i64, h: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, h, 0, 0).unwrap()
}

fn fact(volume: u32, source: &str, key: &str, value: &str) -> FactRow {
    let artifact = if source.ends_with("SAM") { "registry.sam" } else { "registry.system" };
    FactRow { volume: Some(volume), key: key.into(), value: value.into(), artifact: artifact.into(), source: source.into() }
}

/// Facts the Linux parsers produce for a file.
fn linux_facts(volume: u32, path: &str, data: &[u8]) -> Vec<FactRow> {
    let out = strata_artifacts::parse_bytes(path, data).expect("a Linux system file");
    out.facts.into_iter().map(|f| FactRow { volume: Some(volume), key: f.key, value: f.value, artifact: f.artifact, source: f.source }).collect()
}

fn activity(volume: u32, path: &str, kind: ActivityKind, at: Timestamp, count: u64) -> ActivityRow {
    ActivityRow { volume: Some(volume), path: path.into(), kind, hour: at.unix_secs() / 3600, count }
}

fn inputs() -> DiskInputs {
    let xp_system = "WINDOWS/system32/config/SYSTEM";
    let xp_repair = "WINDOWS/repair/system";
    let w7_system = "Windows/System32/config/SYSTEM";
    let old = "Windows.old/WINDOWS/system32/config/SOFTWARE";
    let mut facts = vec![
        fact(1, xp_system, keys::COMPUTER_NAME, "OLGA-XP"),
        fact(1, xp_repair, keys::COMPUTER_NAME, "olga-xp"),
        fact(1, xp_system, keys::TIMEZONE, "Russian Standard Time"),
        fact(1, xp_system, keys::TIMEZONE_BIAS, "-180"),
        fact(1, xp_system, keys::LAST_SHUTDOWN, "2011-02-01 18:00:00"),
        fact(1, "WINDOWS/system32/config/software", keys::WINDOWS_PRODUCT, "Microsoft Windows XP"),
        fact(1, "WINDOWS/system32/config/software", keys::WINDOWS_SERVICE_PACK, "Service Pack 3"),
        fact(1, "WINDOWS/system32/config/software", keys::REGISTERED_OWNER, "Olga"),
        fact(1, "WINDOWS/system32/config/SAM", keys::USER, &to_value(&UserRecord { name: "Olga".into(), logon_count: Some(42), ..Default::default() })),
        fact(1, "WINDOWS/system32/config/SAM", keys::USER, &to_value(&UserRecord { name: "Guest".into(), id: Some("RID 501".into()), ..Default::default() })),
        fact(1, xp_system, keys::USB_DEVICE, &to_value(&UsbRecord { name: "Kingston DataTraveler".into(), kind: "storage".into(), serial: Some("5B8A".into()), last_connected: Some(t(2010, 5, 1, 12)), ..Default::default() })),
        fact(1, "WINDOWS/repair/system", keys::USB_DEVICE, "Kingston DataTraveler (serial 5B8A)"),
        fact(1, "WINDOWS/system32/config/software", keys::NETWORK_PROFILE, &to_value(&NetworkProfileRecord { name: "Cafe42".into(), kind: Some("wireless".into()), ..Default::default() })),
        fact(1, "Documents and Settings/Olga/Recent/wallet.lnk", keys::LNK_MACHINE, "olga-xp"),
        fact(1, "Documents and Settings/Olga/Recent/share.lnk", keys::LNK_MACHINE, "OFFICE-SRV"),
        fact(1, "Documents and Settings/Olga/NTUSER.DAT", keys::WALLET_DATA_DIR, "D:\\BitcoinData"),
        fact(2, w7_system, keys::COMPUTER_NAME, "OLGA-PC"),
        fact(2, w7_system, keys::TIMEZONE, "Russian Standard Time (bias -180 min)"),
        fact(2, "Windows/System32/config/SOFTWARE", keys::WINDOWS_PRODUCT, "Windows 7 Home Premium"),
        fact(2, "Windows/System32/config/SOFTWARE", keys::NETWORK_PROFILE, &to_value(&NetworkProfileRecord {
            name: "HomeWiFi".into(),
            last_connected: Some(t(2013, 7, 2, 12)),
            local_time: true,
            ..Default::default()
        })),
        fact(2, old, keys::WINDOWS_PRODUCT, "Microsoft Windows XP"),
        fact(2, "Windows/System32/config/SOFTWARE", "autorun", "ctfmon = ctfmon.exe"),
    ];
    facts.extend(linux_facts(3, "etc/hostname", b"ubuntu-box\n"));
    facts.extend(linux_facts(3, "etc/os-release", b"PRETTY_NAME=\"Ubuntu 12.04.5 LTS\"\nVERSION_ID=\"12.04\"\n"));
    facts.extend(linux_facts(3, "etc/passwd", b"andrew:x:1000:1000:Andrew Test,,,:/home/andrew:/bin/bash\n"));
    facts.extend(linux_facts(3, "etc/timezone", b"Europe/Moscow\n"));
    facts.extend(linux_facts(3, "var/lib/docker/overlay2/ab12/diff/etc/os-release", b"PRETTY_NAME=\"Alpine Linux v3.7\"\n"));
    let activity = vec![
        activity(1, "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat", ActivityKind::Web, t(2010, 4, 10, 15), 30),
        activity(1, "WINDOWS/Prefetch/BITCOIN.EXE-1A2B.pf", ActivityKind::Program, t(2010, 4, 12, 16), 2),
        activity(2, "Users/Olga/AppData/Local/Google/Chrome/User Data/Default/History", ActivityKind::Web, t(2012, 8, 1, 17), 50),
        activity(4, "andrew/.bash_history", ActivityKind::Program, t(2014, 2, 3, 20), 12),
        activity(3, "var/log/wtmp", ActivityKind::Logon, t(2014, 2, 3, 19), 1),
        activity(5, "Photos/img.jpg", ActivityKind::Document, t(2015, 1, 1, 10), 1),
    ];
    let logons = vec![
        LogonRow { volume: Some(3), path: "var/log/wtmp".into(), title: "Login andrew".into(), last: t(2014, 2, 3, 19), count: 7 },
        LogonRow { volume: Some(2), path: "Windows/System32/winevt/Logs/Security.evtx".into(), title: "Logon: OLGA-PC\\Olga (type 2, interactive)".into(), last: t(2012, 8, 1, 16), count: 3 },
    ];
    let program = |volume, path: &str, evidence, title: &str, at| ProgramRow {
        volume: Some(volume),
        path: path.into(),
        artifact: "t".into(),
        evidence,
        title: title.into(),
        first: at,
        last: at,
        count: 1,
        crypto: true,
    };
    let programs = vec![
        program(1, "WINDOWS/system32/config/software", ProgramEvidence::Installed, "Bitcoin 0.3.21", t(2010, 4, 11, 10)),
        program(1, "WINDOWS/Prefetch/BITCOIN.EXE-1A2B.pf", ProgramEvidence::Ran, "BITCOIN.EXE", t(2010, 4, 12, 16)),
    ];
    DiskInputs { facts, activity, logons, programs, window: UsageWindow::until(t(2016, 1, 1, 0)) }
}

fn by_name<'a>(disk: &'a DiskMachines, name: &str) -> &'a Machine {
    disk.machines.iter().find(|m| m.profile.label() == name).unwrap_or_else(|| panic!("no machine {name}"))
}

#[test]
fn one_profile_per_installation() {
    let disk = DiskMachines::build(&inputs());
    let labels: Vec<String> = disk.machines.iter().map(|m| m.profile.label()).collect();
    assert_eq!(labels, ["OLGA-XP", "OLGA-PC", "ubuntu-box", "Microsoft Windows XP in Windows.old on volume 2", "Alpine Linux v3.7 in var/lib/docker/overlay2/ab12/diff on volume 3"]);
    let old = &disk.machines[3];
    assert_eq!((old.profile.kind, old.profile.key.root.as_str()), (InstallKind::Previous, "Windows.old"));
    assert_eq!(disk.machines[4].profile.kind, InstallKind::Container);
}

#[test]
fn values_are_deduplicated_with_their_sources() {
    let disk = DiskMachines::build(&inputs());
    let xp = by_name(&disk, "OLGA-XP");
    let name = xp.profile.computer_name.primary().unwrap();
    assert_eq!((xp.profile.computer_name.len(), name.seen, name.source().unwrap().file_name()), (1, 2, "SYSTEM"));
    assert_eq!(xp.profile.os.label().as_deref(), Some("Microsoft Windows XP, Service Pack 3"));
    assert_eq!(xp.profile.time_zone.label().as_deref(), Some("Russian Standard Time (UTC+03:00)"));
    assert_eq!(xp.profile.usb.len(), 1, "the old text form merges with the record");
    assert_eq!(xp.profile.linked_machines.iter().map(|m| m.value.as_str()).collect::<Vec<_>>(), ["OFFICE-SRV"]);
    let people: Vec<&str> = xp.profile.people().map(|u| u.name.as_str()).collect();
    assert_eq!(people, ["Olga"], "Guest never logged on");
    assert!(xp.profile.users[0].last_activity.is_some());
    let software: Vec<&str> = xp.profile.software.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(software, ["Bitcoin Core (Bitcoin-Qt, bitcoind)", "Bitcoin 0.3.21"]);
    assert!(xp.profile.software[0].last_used.is_some(), "BITCOIN.EXE runs are Bitcoin Core");
    let w7 = by_name(&disk, "OLGA-PC");
    assert_eq!(w7.profile.time_zone.bias_minutes.value(), Some(&-180), "old `name (bias N min)` facts still read");
    let wifi = &w7.profile.network.profiles[0];
    assert_eq!((wifi.local_time, wifi.last_connected), (false, Some(t(2013, 7, 2, 9))), "local time moved to UTC");
    assert_eq!(w7.profile.users[0].logon_events, 3);
}

#[test]
fn a_home_volume_joins_its_linux_system() {
    let disk = DiskMachines::build(&inputs());
    let ubuntu = by_name(&disk, "ubuntu-box");
    assert_eq!(ubuntu.profile.os.label().as_deref(), Some("Ubuntu 12.04.5 LTS (12.04)"));
    let andrew = ubuntu.profile.users.iter().find(|u| u.name == "andrew").unwrap();
    assert_eq!((andrew.full_name.as_deref(), andrew.logon_events), (Some("Andrew Test"), 7));
    assert!(andrew.last_activity.is_some(), "bash history on the /home volume");
    assert_eq!(ubuntu.usage.active_days, 1);
    assert_eq!(ubuntu.usage.events, 13);
}

#[test]
fn disk_usage_covers_every_installation() {
    let disk = DiskMachines::build(&inputs());
    assert_eq!(disk.usage.range_label().as_deref(), Some("2010-04-10 – 2014-02-03"));
    assert_eq!(disk.usage.outliers.len(), 1, "one photo opened in 2015, eleven months after the rest");
    let xp = by_name(&disk, "OLGA-XP");
    assert_eq!(xp.usage.range_label().as_deref(), Some("2010-04-10 – 2010-04-12"));
    assert_eq!(xp.usage.clock, "UTC+03:00");
    assert_eq!(disk.usage.clock, "UTC+03:00", "every machine agrees on the zone");
}

#[test]
fn activity_classification() {
    assert_eq!(ActivityKind::of(EventKind::SystemLog, "System start (event log service started)"), Some(ActivityKind::Power));
    assert_eq!(ActivityKind::of(EventKind::SystemLog, "restart initiated by Olga (explorer.exe)"), Some(ActivityKind::Power));
    assert_eq!(ActivityKind::of(EventKind::SystemLog, "Service Control Manager event 7036"), None);
    assert_eq!(ActivityKind::of(EventKind::Other, "System shutdown"), Some(ActivityKind::Power));
    assert_eq!(ActivityKind::of(EventKind::Login, "Failed logon: X\\y"), None);
    assert_eq!(ActivityKind::of(EventKind::UrlVisited, "http://example.com"), Some(ActivityKind::Web));
    assert_eq!(ActivityKind::of(EventKind::FileModified, "x"), None);
    assert_eq!(ActivityKind::of(EventKind::ProgramInstalled, "Electrum"), None, "installs are not use");
}
