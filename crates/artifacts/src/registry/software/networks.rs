//! Networks the machine joined. Vista+ `NetworkList` profiles carry the network name, its type,
//! first and last connection (local time) and the gateway's MAC; XP's Wireless Zero
//! Configuration keeps the preferred Wi-Fi networks as `Static#NNNN` blobs.

use crate::host::{NetworkProfileRecord, keys};
use crate::registry::hive::Hive;
use crate::results::Recorder;
use crate::text::{mac_at, systemtime_at};
use std::collections::HashMap;
use strata_kernel::{Confidence, bytes::u32_le};
use strata_timeline::EventKind;

const NETWORK_LIST: &str = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList";
const WZC: &str = "Microsoft\\WZCSVC\\Parameters\\Interfaces";
/// `WZC_WLAN_CONFIG`: BSSID at 8, SSID length at 0x10, SSID bytes at 0x14.
const WZC_BSSID: usize = 8;
const WZC_SSID_LEN: usize = 0x10;
const WZC_SSID: usize = 0x14;

/// Signature data of one profile: gateway MAC and DNS suffix.
#[derive(Default, Clone)]
struct Signature {
    gateway_mac: Option<String>,
    dns_suffix: Option<String>,
}

pub(super) fn parse(h: &Hive<'_>, rec: &mut Recorder) {
    network_list(h, rec);
    wireless_zero_config(h, rec);
}

fn network_list(h: &Hive<'_>, rec: &mut Recorder) {
    let Some(profiles) = h.open(&format!("{NETWORK_LIST}\\Profiles")) else { return };
    let signatures = signatures(h);
    for key in h.subkeys(&profiles) {
        let Some(name) = h.text(&key, "ProfileName").or_else(|| h.text(&key, "Description")) else { continue };
        let at = |n: &str| h.value(&key, n).and_then(|v| systemtime_at(&v.data, 0));
        let kind = match h.value(&key, "NameType").and_then(|v| v.dword()) {
            Some(0x47) => Some("wireless"),
            Some(0x06) => Some("wired"),
            Some(0xF3) => Some("mobile broadband"),
            Some(0x17) => Some("broadband"),
            _ => None,
        };
        let sig = signatures.get(&key.name.to_ascii_uppercase()).cloned().unwrap_or_default();
        let profile = NetworkProfileRecord {
            name,
            kind: kind.map(str::to_string),
            first_connected: at("DateCreated"),
            last_connected: at("DateLastConnected"),
            local_time: true,
            gateway_mac: sig.gateway_mac,
            dns_suffix: sig.dns_suffix,
            ..Default::default()
        };
        for (t, what) in [(profile.first_connected, "first connected"), (profile.last_connected, "last connected")] {
            if let Some(e) = rec.make(t, EventKind::Other, format!("Network {what}: {}", profile.name)) {
                rec.push(e.with_detail("NetworkList profile; machine local time").with_confidence(Confidence::LOW));
            }
        }
        rec.record(keys::NETWORK_PROFILE, &profile);
    }
}

/// `Signatures\{Managed,Unmanaged}\<id>`: profile GUID → gateway MAC and DNS suffix.
fn signatures(h: &Hive<'_>) -> HashMap<String, Signature> {
    let mut out = HashMap::new();
    for group in ["Managed", "Unmanaged"] {
        let Some(key) = h.open(&format!("{NETWORK_LIST}\\Signatures\\{group}")) else { continue };
        for sig in h.subkeys(&key) {
            let Some(guid) = h.text(&sig, "ProfileGuid") else { continue };
            let gateway_mac = h.value(&sig, "DefaultGatewayMac").and_then(|v| mac_at(&v.data, 0));
            let dns_suffix = h.text(&sig, "DnsSuffix").filter(|s| s != "<none>");
            out.insert(guid.to_ascii_uppercase(), Signature { gateway_mac, dns_suffix });
        }
    }
    out
}

/// XP preferred wireless networks: SSID and access point MAC per `Static#NNNN` value.
fn wireless_zero_config(h: &Hive<'_>, rec: &mut Recorder) {
    let Some(interfaces) = h.open(WZC) else { return };
    for interface in h.subkeys(&interfaces) {
        for v in h.values(&interface).into_iter().filter(|v| v.name.starts_with("Static#")) {
            let len = u32_le(&v.data, WZC_SSID_LEN).map_or(0, |n| n as usize);
            let Some(raw) = v.data.get(WZC_SSID..WZC_SSID + len).filter(|_| (1..=32).contains(&len)) else { continue };
            let ssid = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
            if ssid.chars().any(char::is_control) {
                continue;
            }
            let profile = NetworkProfileRecord {
                name: ssid,
                kind: Some("wireless".into()),
                bssid: mac_at(&v.data, WZC_BSSID),
                ..Default::default()
            };
            rec.record(keys::NETWORK_PROFILE, &profile);
        }
    }
}
