use super::testkit::{ChunkBuilder, FT, Xml, event_template, event_values, evtx_file, sample_log};
use super::*;
use crate::results::{ArtifactResults, IdentityKind};
use strata_timeline::EventKind;

fn run(data: &[u8]) -> ArtifactResults {
    let mut rec = Recorder::new("windows.evtx");
    Evtx::parse(data, &mut rec);
    rec.finish()
}

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

#[test]
fn logons_and_boot_from_templates() {
    let data = sample_log();
    assert!(Evtx::is_evtx(&data));
    let out = run(&data);
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    assert_eq!(out.events.len(), 3, "{:#?}", out.events);
    let logon = &out.events[0];
    assert_eq!(logon.kind(), EventKind::Login);
    assert_eq!(logon.title(), "Logon: ADMIN-PC\\Admin (type 2, interactive)");
    assert_eq!(logon.actor(), Some("Admin"));
    assert_eq!(logon.at().to_string(), "2011-05-14 17:36:09");
    assert!(logon.detail().contains("computer ADMIN-PC") && logon.detail().contains("channel Security"), "{}", logon.detail());
    assert_eq!(out.events[1].title(), "Failed logon: bitcoin (type 10, remote interactive (RDP))");
    assert_eq!(out.events[1].at().to_string(), "2011-05-14 17:36:10");
    assert_eq!(out.events[2].kind(), EventKind::SystemLog);
    assert!(out.events[2].title().starts_with("System start"));
    assert_eq!(out.identities.len(), 1);
    assert_eq!((out.identities[0].kind, out.identities[0].value.as_str()), (IdentityKind::Login, "Admin"));
}

/// UserData events written without substitutions (static text tokens only).
fn rdp_logon(x: &mut Xml<'_>) {
    x.fragment();
    x.open("Event", false);
    x.close_start();
    x.open("System", false);
    x.close_start();
    x.open("Provider", true);
    x.attr("Name");
    x.text("Microsoft-Windows-TerminalServices-LocalSessionManager");
    x.close_empty();
    x.open("EventID", false);
    x.close_start();
    x.text("21");
    x.end();
    x.open("TimeCreated", true);
    x.attr("SystemTime");
    x.text("2012-01-31T19:57:06.123Z");
    x.close_empty();
    x.end();
    x.open("UserData", false);
    x.close_start();
    x.open("EventXML", false);
    x.close_start();
    x.data(None, "ignored");
    x.open("User", false);
    x.close_start();
    x.text("ADMIN-PC\\Admin");
    x.end();
    x.open("Address", false);
    x.close_start();
    x.text("10.0.0.7");
    x.end();
    x.end();
    x.end();
    x.end();
    x.eof();
}

#[test]
fn installs_services_sessions_and_generic_events() {
    let mut c = ChunkBuilder::default();
    let tpl = c.record(1, FT, |x| {
        x.fragment();
        let svc = [("ServiceName", "WalletSvc"), ("ImagePath", "C:\\w\\svc.exe"), ("AccountName", "LocalSystem")];
        x.template(Some(&event_template), 0, event_values("Service Control Manager", 7045, FT, "System", &svc))
    });
    c.record(2, FT, |x| {
        x.fragment();
        let msi = [("", "Bitcoin Core"), ("", "0.8.6"), ("", "1033"), ("", "0")];
        x.template(None, tpl, event_values("MsiInstaller", 1033, FT, "Application", &msi));
    });
    c.record(3, FT, rdp_logon);
    c.record(4, FT, |x| {
        x.fragment();
        x.template(None, tpl, event_values("Some-Provider", 42, FT, "", &[("Key", "Value")]));
    });
    let out = run(&evtx_file(&[c.finish()]));
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    let titles: Vec<(&str, EventKind)> = out.events.iter().map(|e| (e.title(), e.kind())).collect();
    assert_eq!(
        titles,
        vec![
            ("Service installed: WalletSvc (C:\\w\\svc.exe)", EventKind::ProgramInstalled),
            ("Installed: Bitcoin Core", EventKind::ProgramInstalled),
            ("Session logon: ADMIN-PC\\Admin from 10.0.0.7", EventKind::Login),
            ("Some-Provider event 42", EventKind::SystemLog),
        ]
    );
    assert_eq!(out.events[2].at().to_string(), "2012-01-31 19:57:06");
    assert!(out.events[3].detail().contains("Key=Value"));
}

#[test]
fn chunks_are_carved_without_a_file_header() {
    let log = sample_log();
    let chunk = &log[0x1000..];
    let mut buf = noise(777, 3);
    buf.extend_from_slice(chunk);
    buf.extend(noise(5000, 4));
    buf.extend_from_slice(b"ElfChnk\0 but nothing else");
    let out = run(&buf);
    assert_eq!(out.events.len(), 3);
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    assert!(Evtx::is_evtx(chunk));
    assert_eq!(run(chunk).events.len(), 3);
}

#[test]
fn checksum_mismatches_are_damage_but_records_survive() {
    let mut data = sample_log();
    // The stored records checksum (inside the chunk header) and a file header byte.
    data[0x1000 + 52] ^= 0xFF;
    data[50] ^= 0xFF;
    let out = run(&data);
    let notes: Vec<&str> = out.damage.iter().map(|d| d.note()).collect();
    assert!(notes.contains(&"EVTX file header checksum mismatch"), "{notes:?}");
    assert!(notes.contains(&"EVTX chunk header checksum mismatch"), "{notes:?}");
    assert!(notes.contains(&"EVTX chunk records checksum mismatch"), "{notes:?}");
    assert_eq!(out.events.len(), 3);
}

#[test]
fn hostile_input_never_panics() {
    let log = sample_log();
    for cut in (0..log.len()).step_by(997).chain(0x1000..0x1400) {
        let _ = run(&log[..cut]);
    }
    for seed in 1..200u64 {
        let mut data = log.clone();
        let flips = noise(16, seed);
        for pair in flips.chunks(2) {
            let at = 0x1200 + (usize::from(pair[0]) * 7 + usize::from(pair[1]) * 3) % 0x400;
            data[at] ^= pair[1] | 1;
        }
        let _ = run(&data);
        let mut junk = b"ElfChnk\0".to_vec();
        junk.extend(noise(70_000, seed));
        let _ = run(&junk);
        let mut junk = log[..0x1200].to_vec();
        junk.extend(noise(0x3000, seed));
        let _ = run(&junk);
    }
}
