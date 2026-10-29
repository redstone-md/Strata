use super::*;
use crate::host::{NetworkInterfaceRecord, NetworkProfileRecord, UserRecord, from_value};

fn parse(path: &str, data: &[u8]) -> crate::results::ArtifactResults {
    let mut rec = Recorder::new("linux.system");
    LinuxSystem::parse(path, data, &mut rec);
    rec.finish()
}

fn fact<'a>(out: &'a crate::results::ArtifactResults, key: &str) -> Vec<&'a str> {
    out.facts.iter().filter(|f| f.key == key).map(|f| f.value.as_str()).collect()
}

#[test]
fn host_name_distribution_and_time_zone() {
    assert!(LinuxSystem::matches("etc/hostname") && LinuxSystem::matches("ETC\\NetworkManager\\system-connections\\Home"));
    assert!(!LinuxSystem::matches("home/u/etc/notes.txt"));
    assert_eq!(fact(&parse("etc/hostname", b"# set by installer\nubuntu-box\n"), keys::COMPUTER_NAME), ["ubuntu-box"]);
    let os = parse("usr/lib/os-release", b"NAME=\"Ubuntu\"\nVERSION_ID=\"12.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 12.04.5 LTS\"\n");
    assert_eq!(fact(&os, keys::LINUX_DISTRO), ["Ubuntu 12.04.5 LTS"]);
    assert_eq!((fact(&os, keys::LINUX_DISTRO_ID), fact(&os, keys::LINUX_VERSION)), (vec!["ubuntu"], vec!["12.04"]));
    assert_eq!(fact(&parse("etc/redhat-release", b"CentOS release 5.5 (Final)\n"), keys::LINUX_DISTRO), ["CentOS release 5.5 (Final)"]);
    assert_eq!(fact(&parse("etc/timezone", b"Europe/Moscow\n"), keys::TIMEZONE), ["Europe/Moscow"]);
    let mut tzif = b"TZif2\0\0\0junk".to_vec();
    tzif.extend_from_slice(b"\n<+03>-3\n");
    let tz = parse("etc/localtime", &tzif);
    assert_eq!((fact(&tz, keys::TIMEZONE), fact(&tz, keys::TIMEZONE_BIAS)), (vec!["+03"], vec!["-180"]));
    assert_eq!(posix_tz("EST5EDT,M3.2.0,M11.1.0"), Some(("EST".into(), 300)));
    assert_eq!(posix_tz("IST-5:30"), Some(("IST".into(), -330)));
    assert_eq!(posix_tz("garbage"), None);
}

#[test]
fn people_from_passwd() {
    let out = parse("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n\
andrew:x:1000:1000:Andrew Test,,,:/home/andrew:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/bin/sh\nbroken::line\n");
    let users: Vec<UserRecord> = fact(&out, keys::USER).iter().filter_map(|v| from_value(v)).collect();
    assert_eq!(users.len(), 1);
    assert_eq!((users[0].name.as_str(), users[0].full_name.as_deref(), users[0].home.as_deref()), ("andrew", Some("Andrew Test"), Some("/home/andrew")));
}

#[test]
fn network_manager_connections_and_leases() {
    let keyfile = b"[connection]\nid=HomeNet\nuuid=1\ntype=802-11-wireless\ntimestamp=1367000000\n\n[802-11-wireless]\nssid=72;111;109;101;\nmac-address=00:11:22:aa:bb:cc\n";
    let out = parse("etc/NetworkManager/system-connections/HomeNet", keyfile);
    let p: NetworkProfileRecord = from_value(fact(&out, keys::NETWORK_PROFILE)[0]).unwrap();
    assert_eq!((p.name.as_str(), p.kind.as_deref(), p.mac.as_deref()), ("HomeNet (SSID Home)", Some("wireless"), Some("00:11:22:AA:BB:CC")));
    assert_eq!(p.last_connected.map(|t| t.to_string()).as_deref(), Some("2013-04-26 18:13:20"));
    let leases = b"lease {\n  interface \"eth0\";\n  fixed-address 192.168.1.5;\n  option routers 192.168.1.1;\n  option domain-name-servers 8.8.8.8,8.8.4.4;\n}\nlease {\n  interface \"eth0\";\n  fixed-address 192.168.1.5;\n  option routers 192.168.1.1;\n  option domain-name-servers 8.8.8.8,8.8.4.4;\n}\nlease { broken";
    let out = parse("var/lib/dhcp/dhclient.eth0.leases", leases);
    let ifaces: Vec<NetworkInterfaceRecord> = fact(&out, keys::NETWORK_INTERFACE).iter().filter_map(|v| from_value(v)).collect();
    assert_eq!(ifaces.len(), 1);
    assert_eq!((ifaces[0].id.as_str(), ifaces[0].addresses.clone(), ifaces[0].dns.len()), ("eth0", vec!["192.168.1.5".to_string()], 2));
}

#[test]
fn garbage_never_panics() {
    for path in ["etc/hostname", "etc/os-release", "etc/localtime", "etc/passwd", "etc/NetworkManager/system-connections/x", "var/lib/dhcp/x.leases"] {
        for data in [&b""[..], b"\xff\xfe\x00", b"TZif", b"lease {", b"[connection", b"a:b:c:d:e:f:g:h"] {
            let _ = parse(path, data);
        }
    }
}
