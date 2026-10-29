//! `cargo run -p strata-workbench --example demo_machines -- <dir>`: build a case with host
//! facts and user activity of three made-up installations (Windows XP and Windows 7 on one
//! disk, Ubuntu on another) plus thousands of raw facts, for UI work on the Disks screen. Two
//! blank images, no real evidence.

use std::path::Path;
use strata_case::HostFact;
use strata_kernel::{EvidenceId, Timestamp};
use strata_timeline::{EventKind, EventSource, TimelineEvent};
use strata_workbench::Workbench;

fn at(y: i64, m: i64, d: i64, h: i64) -> Timestamp {
    Timestamp::from_civil(y, m, d, h, 0, 0).expect("valid demo date")
}

fn blank_image(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, vec![0u8; 1 << 20]).expect("write blank image");
    path.display().to_string()
}

struct Facts {
    disk: EvidenceId,
    rows: Vec<HostFact>,
}

impl Facts {
    fn add(&mut self, volume: u32, source: &str, key: &str, value: &str) {
        let artifact = if source.contains("etc/") { "linux.system" } else { "registry.system" };
        self.rows.push(HostFact { evidence: self.disk, volume: Some(volume), key: key.into(), value: value.into(), artifact: artifact.into(), source: source.into() });
    }
}

fn event(t: Timestamp, kind: EventKind, title: &str, artifact: &str, path: &str) -> TimelineEvent {
    TimelineEvent::new(t, kind, title, EventSource::new(artifact, path))
}

/// Evening sessions on `days` days of each month in `months`.
fn sessions(year: i64, months: std::ops::RangeInclusive<i64>, days: &[i64], path: &str, artifact: &str, kind: EventKind) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    for m in months {
        for d in days {
            for h in [18, 19, 20, 21] {
                out.push(event(at(year, m, *d, h), kind, "http://example.com/forum", artifact, path));
            }
        }
    }
    out
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: demo_machines <dir>");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("create the demo folder");
    let wb = Workbench::open_idle(&dir.join("machines-demo.strata")).expect("open the demo case");
    let laptop = wb.add_evidence(&blank_image(dir, "home-pc.img")).expect("add disk").id;
    let server = wb.add_evidence(&blank_image(dir, "ubuntu.img")).expect("add disk").id;

    let (sys, soft, sam) = ("WINDOWS/system32/config/SYSTEM", "WINDOWS/system32/config/software", "WINDOWS/system32/config/SAM");
    let mut f = Facts { disk: laptop, rows: Vec::new() };
    for (k, v) in [("computer_name", "OLGA-XP"), ("timezone", "Russian Standard Time"), ("timezone_bias", "-180"), ("last_shutdown", "2011-02-01 18:04:12")] {
        f.add(0, sys, k, v);
        f.add(0, "WINDOWS/repair/system", k, v);
    }
    f.add(0, sys, "hw_cpu", "Intel(R) Pentium(R) 4 CPU 3.00GHz");
    f.add(0, sys, "hw_video", "NVIDIA GeForce 6600");
    f.add(0, sys, "network_interface", r#"{"id":"{A1}","adapter":"Realtek RTL8139","addresses":["192.168.1.34"],"dhcp":true,"gateways":["192.168.1.1"]}"#);
    f.add(0, sys, "usb_device", r#"{"name":"Kingston DataTraveler 2.0 USB Device","kind":"storage","serial":"5B8A1C2D","last_connected":"2010-11-20 17:02:00","approximate":true}"#);
    f.add(0, sys, "usb_device", r#"{"name":"Ledger Nano S","kind":"hardware wallet","serial":"0001","last_connected":"2010-12-02 19:40:00","approximate":true}"#);
    for (k, v) in [("windows_product", "Microsoft Windows XP"), ("windows_service_pack", "Service Pack 3"), ("windows_version", "5.1"), ("windows_build", "2600"), ("registered_owner", "Olga"), ("install_date", "2008-02-11 10:15:00"), ("system_root", "C:\\WINDOWS")] {
        f.add(0, soft, k, v);
    }
    f.add(0, soft, "network_profile", r#"{"name":"Cafe42","kind":"wireless","local_time":false,"bssid":"00:1A:2B:3C:4D:5E"}"#);
    f.add(0, sam, "user", r#"{"name":"Olga","id":"RID 1003","last_logon":"2011-02-01 17:10:00","logon_count":812}"#);
    f.add(0, sam, "user", r#"{"name":"Guest","id":"RID 501"}"#);
    f.add(0, "Documents and Settings/Olga/NTUSER.DAT", "wallet_data_dir", "D:\\BitcoinData");
    let w7 = "Windows/System32/config/SYSTEM";
    for (k, v) in [("computer_name", "OLGA-PC"), ("timezone", "Russian Standard Time"), ("timezone_bias", "-180"), ("last_shutdown", "2013-07-02 22:41:09")] {
        f.add(1, w7, k, v);
    }
    for (k, v) in [("windows_product", "Windows 7 Home Premium"), ("windows_service_pack", "Service Pack 1"), ("windows_version", "6.1"), ("windows_build", "7601"), ("registered_owner", "Olga"), ("install_date", "2011-02-03 12:00:00")] {
        f.add(1, "Windows/System32/config/SOFTWARE", k, v);
    }
    f.add(1, "Windows/System32/config/SOFTWARE", "network_profile", r#"{"name":"HomeWiFi","kind":"wireless","first_connected":"2011-02-04 10:00:00","last_connected":"2013-07-02 21:00:00","local_time":true}"#);
    f.add(1, "Windows/System32/config/SAM", "user", r#"{"name":"Olga","id":"RID 1000","last_logon":"2013-07-02 18:00:00","logon_count":540}"#);
    // Noise of the old Machine list: thousands of undated traces and repeated LNK machine ids.
    for i in 0..3000 {
        f.add(0, "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat", "url", &format!("http://example.com/page/{i}"));
    }
    for i in 0..60 {
        f.add(0, &format!("Documents and Settings/Olga/Recent/doc{i}.lnk"), "machine_id", "olga-xp");
    }
    let rows = std::mem::take(&mut f.rows);
    let mut u = Facts { disk: server, rows: Vec::new() };
    for (k, v) in [("computer_name", "ubuntu-box"), ("linux_distro", "Ubuntu 12.04.5 LTS"), ("linux_version", "12.04"), ("timezone", "Europe/Moscow")] {
        u.add(0, "etc/hostname", k, v);
    }
    u.add(0, "etc/passwd", "user", r#"{"name":"andrew","full_name":"Andrew Test","id":"uid 1000","home":"/home/andrew","shell":"/bin/bash"}"#);

    let xp_history = "Documents and Settings/Olga/Local Settings/History/History.IE5/index.dat";
    let mut xp = sessions(2009, 3..=12, &[2, 5, 9, 14, 20, 27], xp_history, "ie.index_dat", EventKind::UrlVisited);
    xp.extend(sessions(2010, 1..=11, &[3, 11, 19, 25], xp_history, "ie.index_dat", EventKind::UrlVisited));
    xp.push(event(at(2003, 1, 1, 0), EventKind::DocumentOpened, "C:\\boot.ini", "windows.lnk", "Documents and Settings/Olga/Recent/boot.lnk"));
    xp.push(event(at(2010, 4, 12, 19), EventKind::ProgramRun, "BITCOIN.EXE", "windows.prefetch", "WINDOWS/Prefetch/BITCOIN.EXE-1A2B3C4D.pf"));
    xp.push(event(at(2010, 4, 11, 10), EventKind::ProgramInstalled, "Bitcoin 0.3.21", "registry.software", soft).with_tag("crypto"));
    let w7_history = "Users/Olga/AppData/Local/Google/Chrome/User Data/Default/History";
    let mut w7e = sessions(2011, 2..=12, &[1, 8, 15, 22], w7_history, "chrome.history", EventKind::UrlVisited);
    w7e.extend(sessions(2013, 3..=7, &[2, 16], w7_history, "chrome.history", EventKind::UrlVisited));
    w7e.push(event(at(2012, 6, 1, 20), EventKind::ProgramRun, "%ProgramFiles%\\Electrum\\electrum.exe", "registry.ntuser", "Users/Olga/NTUSER.DAT"));
    let wtmp: Vec<TimelineEvent> = (1..=20).map(|d| event(at(2014, 1, d, 9), EventKind::Login, "Login andrew", "linux.wtmp", "var/log/wtmp")).collect();
    let mut bash: Vec<TimelineEvent> = (1..=20).map(|d| event(at(2014, 1, d, 10), EventKind::ProgramRun, "electrum --offline", "linux.shell_history", "home/andrew/.bash_history")).collect();
    bash.extend(wtmp);
    wb.case()
        .write(|w| {
            w.facts(&rows)?;
            w.facts(&u.rows)?;
            w.volume_events(laptop, 0, &xp)?;
            w.volume_events(laptop, 1, &w7e)?;
            w.volume_events(server, 0, &bash)
        })
        .expect("store the demo facts and events");
    wb.set_ui_state(r#"{"screen":"disks"}"#).expect("open on the Disks screen");
    println!("{}", dir.join("machines-demo.strata").display());
}
