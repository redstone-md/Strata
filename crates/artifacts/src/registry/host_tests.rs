//! Machine details from synthetic SYSTEM, SOFTWARE and SAM hives.

use super::hive::{REG_DWORD, REG_MULTI_SZ, REG_SZ};
use super::hive_testutil::{HiveBuilder, sz};
use super::*;
use crate::host::{NetworkInterfaceRecord, NetworkProfileRecord, UsbRecord, UserRecord, from_value, keys};
use crate::results::ArtifactResults;

/// 2012-01-31 19:57:06 UTC.
const FT2: u64 = 129_725_134_260_000_000;
const CS: &str = "ControlSet001";

fn multi(items: &[&str]) -> Vec<u8> {
    let mut out: Vec<u8> = items.iter().flat_map(|s| sz(s)).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

fn facts<'a>(out: &'a ArtifactResults, key: &str) -> Vec<&'a str> {
    out.facts.iter().filter(|f| f.key == key).map(|f| f.value.as_str()).collect()
}

fn records<T: serde::de::DeserializeOwned>(out: &ArtifactResults, key: &str) -> Vec<T> {
    facts(out, key).iter().filter_map(|v| from_value(v)).collect()
}

/// SYSTEMTIME bytes.
fn systemtime(y: u16, mo: u16, d: u16, h: u16, mi: u16) -> Vec<u8> {
    [y, mo, 0, d, h, mi, 0, 0].iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[test]
fn system_hive_identity_network_hardware_usb() {
    let mut b = HiveBuilder::new();
    b.value("Select", "Current", REG_DWORD, &1u32.to_le_bytes());
    b.value(&format!("{CS}\\Control\\ComputerName\\ComputerName"), "ComputerName", REG_SZ, &sz("HOME-PC"));
    b.value(&format!("{CS}\\Services\\Tcpip\\Parameters"), "Domain", REG_SZ, &sz("corp.example"));
    let tz = format!("{CS}\\Control\\TimeZoneInformation");
    b.value(&tz, "StandardName", REG_SZ, &sz("Russian Standard Time"));
    b.value(&tz, "Bias", REG_DWORD, &(-180i32).to_le_bytes());
    b.value(&format!("{CS}\\Control\\Windows"), "ShutdownTime", 3, &FT2.to_le_bytes());
    let guid = "{AAAA1111-2222-3333-4444-555566667777}";
    let iface = format!("{CS}\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}");
    b.value(&iface, "EnableDHCP", REG_DWORD, &1u32.to_le_bytes());
    b.value(&iface, "DhcpIPAddress", REG_SZ, &sz("192.168.0.10"));
    b.value(&iface, "DhcpDefaultGateway", REG_MULTI_SZ, &multi(&["192.168.0.1"]));
    b.value(&iface, "DhcpNameServer", REG_SZ, &sz("192.168.0.1 8.8.8.8"));
    b.value(&iface, "DhcpServer", REG_SZ, &sz("192.168.0.1"));
    b.value(&iface, "LeaseObtainedTime", REG_DWORD, &1_300_000_000u32.to_le_bytes());
    b.value(&format!("{CS}\\Services\\Tcpip\\Parameters\\Interfaces\\{{EMPTY}}"), "IPAddress", REG_MULTI_SZ, &multi(&["0.0.0.0"]));
    let adapter = format!("{CS}\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\0007");
    b.value(&adapter, "DriverDesc", REG_SZ, &sz("Realtek RTL8139 Family PCI Fast Ethernet NIC"));
    b.value(&adapter, "NetCfgInstanceId", REG_SZ, &sz(&guid.to_lowercase()));
    b.value(&adapter, "NetworkAddress", REG_SZ, &sz("001122aabbcc"));
    for core in ["_0", "_1"] {
        b.value(&format!("{CS}\\Enum\\ACPI\\GenuineIntel_-_x86_Family_6_Model_23\\{core}"), "FriendlyName", REG_SZ, &sz("Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz"));
    }
    b.value(&format!("{CS}\\Control\\Class\\{{4D36E968-E325-11CE-BFC1-08002BE10318}}\\0000"), "DriverDesc", REG_SZ, &sz("NVIDIA GeForce 8600 GT"));
    b.value(&format!("{CS}\\Control\\SystemInformation"), "SystemManufacturer", REG_SZ, &sz("ASUSTeK"));
    b.value(&format!("{CS}\\Control\\SystemInformation"), "SystemProductName", REG_SZ, &sz("P5Q"));
    b.key(&format!("{CS}\\Enum\\IDE\\DiskST3500418AS_____________________________CC38____\\5&1&0&0.0.0"));
    let ledger = format!("{CS}\\Enum\\USB\\VID_2C97&PID_0001\\0001");
    b.value(&ledger, "DeviceDesc", REG_SZ, &sz("@oem12.inf,%desc%;Nano S"));
    b.key_time(&ledger, FT2);
    b.value(&format!("{CS}\\Enum\\USB\\VID_046D&PID_C52B\\5&1"), "DeviceDesc", REG_SZ, &sz("USB Receiver"));
    let out = parse_hive(&b.build());
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    assert_eq!(facts(&out, keys::COMPUTER_NAME), ["HOME-PC"]);
    assert_eq!(facts(&out, keys::DOMAIN), ["corp.example"]);
    assert_eq!((facts(&out, keys::TIMEZONE), facts(&out, keys::TIMEZONE_BIAS)), (vec!["Russian Standard Time"], vec!["-180"]));
    assert_eq!(facts(&out, keys::LAST_SHUTDOWN), ["2012-01-31 19:57:06"]);
    let ifaces: Vec<NetworkInterfaceRecord> = records(&out, keys::NETWORK_INTERFACE);
    assert_eq!(ifaces.len(), 1, "interfaces without an address are left out");
    let i = &ifaces[0];
    assert_eq!(i.adapter.as_deref(), Some("Realtek RTL8139 Family PCI Fast Ethernet NIC"));
    assert_eq!((i.addresses.clone(), i.dns.len(), i.mac.as_deref()), (vec!["192.168.0.10".to_string()], 2, Some("00:11:22:AA:BB:CC")));
    assert_eq!(i.lease_obtained.map(|t| t.to_string()).as_deref(), Some("2011-03-13 07:06:40"));
    assert_eq!(facts(&out, keys::CPU), ["Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz × 2"]);
    assert_eq!(facts(&out, keys::VIDEO), ["NVIDIA GeForce 8600 GT"]);
    assert_eq!(facts(&out, keys::SYSTEM_MODEL), ["ASUSTeK P5Q"]);
    assert_eq!(facts(&out, keys::DISK_DRIVE), ["ST3500418AS"]);
    let usb: Vec<UsbRecord> = records(&out, keys::USB_DEVICE);
    assert_eq!(usb.len(), 1, "only hardware wallets among plain USB devices");
    assert_eq!((usb[0].name.as_str(), usb[0].kind.as_str(), usb[0].approximate), ("Ledger Nano S", "hardware wallet", true));
    let event = out.events.iter().find(|e| e.kind() == EventKind::UsbDevice).unwrap();
    assert!(event.is_crypto());
}

#[test]
fn software_hive_version_profiles_networks() {
    let mut b = HiveBuilder::new();
    b.key("Classes").key("Policies");
    let nt = "Microsoft\\Windows NT\\CurrentVersion";
    b.value(nt, "ProductName", REG_SZ, &sz("Windows 7 Ultimate"));
    b.value(nt, "EditionID", REG_SZ, &sz("Ultimate"));
    b.value(nt, "CurrentVersion", REG_SZ, &sz("6.1"));
    b.value(nt, "CurrentBuildNumber", REG_SZ, &sz("7601"));
    b.value(nt, "CSDVersion", REG_SZ, &sz("Service Pack 1"));
    b.value(nt, "SystemRoot", REG_SZ, &sz("C:\\Windows"));
    b.value(nt, "InstallDate", REG_DWORD, &1_300_000_000u32.to_le_bytes());
    let sid = format!("{nt}\\ProfileList\\S-1-5-21-1-2-3-1000");
    b.value(&sid, "ProfileImagePath", REG_SZ, &sz("C:\\Users\\Olga"));
    b.value(&sid, "ProfileLoadTimeHigh", REG_DWORD, &((FT2 >> 32) as u32).to_le_bytes());
    b.value(&sid, "ProfileLoadTimeLow", REG_DWORD, &(FT2 as u32).to_le_bytes());
    b.value(&format!("{nt}\\ProfileList\\S-1-5-18"), "ProfileImagePath", REG_SZ, &sz("%systemroot%\\system32\\config\\systemprofile"));
    let guid = "{0F0F0F0F-1111-2222-3333-444444444444}";
    let profile = format!("{nt}\\NetworkList\\Profiles\\{guid}");
    b.value(&profile, "ProfileName", REG_SZ, &sz("HomeWiFi"));
    b.value(&profile, "NameType", REG_DWORD, &0x47u32.to_le_bytes());
    b.value(&profile, "DateCreated", 3, &systemtime(2011, 3, 1, 18, 30));
    b.value(&profile, "DateLastConnected", 3, &systemtime(2013, 7, 2, 9, 15));
    let sig = format!("{nt}\\NetworkList\\Signatures\\Unmanaged\\0102");
    b.value(&sig, "ProfileGuid", REG_SZ, &sz(guid));
    b.value(&sig, "DefaultGatewayMac", 3, &[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    let mut wzc = vec![0u8; 0x40];
    wzc[8..14].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    wzc[0x10..0x14].copy_from_slice(&6u32.to_le_bytes());
    wzc[0x14..0x1A].copy_from_slice(b"Cafe42");
    b.value("Microsoft\\WZCSVC\\Parameters\\Interfaces\\{X}", "Static#0000", 3, &wzc);
    b.value("Microsoft\\WZCSVC\\Parameters\\Interfaces\\{X}", "Static#0001", 3, &[0xFF; 8]);
    let out = parse_hive(&b.build());
    for (key, value) in [
        (keys::WINDOWS_EDITION, "Ultimate"),
        (keys::WINDOWS_VERSION, "6.1"),
        (keys::WINDOWS_BUILD, "7601"),
        (keys::WINDOWS_SERVICE_PACK, "Service Pack 1"),
        (keys::SYSTEM_ROOT, "C:\\Windows"),
        (keys::INSTALL_DATE, "2011-03-13 07:06:40"),
    ] {
        assert_eq!(facts(&out, key), [value], "{key}");
    }
    let users: Vec<UserRecord> = records(&out, keys::USER);
    assert_eq!(users.len(), 1, "service profiles are not people");
    assert_eq!((users[0].name.as_str(), users[0].home.as_deref()), ("Olga", Some("C:\\Users\\Olga")));
    assert_eq!(users[0].profile_loaded.map(|t| t.to_string()).as_deref(), Some("2012-01-31 19:57:06"));
    let nets: Vec<NetworkProfileRecord> = records(&out, keys::NETWORK_PROFILE);
    let home = nets.iter().find(|n| n.name == "HomeWiFi").unwrap();
    assert_eq!((home.kind.as_deref(), home.gateway_mac.as_deref(), home.local_time), (Some("wireless"), Some("00:1A:2B:3C:4D:5E"), true));
    assert_eq!(home.last_connected.map(|t| t.to_string()).as_deref(), Some("2013-07-02 09:15:00"));
    let cafe = nets.iter().find(|n| n.name == "Cafe42").expect("XP wireless network");
    assert_eq!(cafe.bssid.as_deref(), Some("01:02:03:04:05:06"));
    assert_eq!(nets.len(), 2, "a broken Static# blob is skipped");
    assert!(out.events.iter().any(|e| e.title() == "Network last connected: HomeWiFi"));
}

#[test]
fn sam_users_with_full_name() {
    let mut b = HiveBuilder::new();
    b.value("SAM\\Domains\\Account\\Users\\Names\\Olga", "", 0x3E8, &[]);
    let mut f = vec![0u8; 80];
    f[8..16].copy_from_slice(&FT2.to_le_bytes());
    f[66..68].copy_from_slice(&17u16.to_le_bytes());
    let full: Vec<u8> = "Olga Test".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = vec![0u8; 0xCC];
    v[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
    v[0x1C..0x20].copy_from_slice(&(full.len() as u32).to_le_bytes());
    v.extend_from_slice(&full);
    b.value("SAM\\Domains\\Account\\Users\\000003E8", "F", 3, &f);
    b.value("SAM\\Domains\\Account\\Users\\000003E8", "V", 3, &v);
    let mut broken = vec![0u8; 0x20];
    broken[0x18..0x1C].copy_from_slice(&u32::MAX.to_le_bytes());
    b.value("SAM\\Domains\\Account\\Users\\Names\\Guest", "", 0x1F5, &[]);
    b.value("SAM\\Domains\\Account\\Users\\000001F5", "V", 3, &broken);
    let out = parse_hive(&b.build());
    let users: Vec<UserRecord> = records(&out, keys::USER);
    let olga = users.iter().find(|u| u.name == "Olga").unwrap();
    assert_eq!((olga.full_name.as_deref(), olga.logon_count, olga.id.as_deref()), (Some("Olga Test"), Some(17), Some("RID 1000")));
    assert_eq!(olga.last_logon.map(|t| t.to_string()).as_deref(), Some("2012-01-31 19:57:06"));
    let guest = users.iter().find(|u| u.name == "Guest").unwrap();
    assert_eq!((guest.full_name.as_ref(), guest.last_logon), (None, None));
}
