//! TCP/IP configuration: one record per interface that had an address, named after its
//! network adapter (`Control\Class\{4D36E972…}`), with gateways, DHCP and DNS servers.

use super::{ControlSet, list};
use crate::host::{NetworkInterfaceRecord, keys};
use crate::results::Recorder;
use std::collections::HashMap;
use strata_kernel::Timestamp;

/// Device class of network adapters.
const ADAPTERS: &str = "Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
const INTERFACES: &str = "Services\\Tcpip\\Parameters\\Interfaces";

pub(super) fn parse(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
    let adapters = adapters(cs);
    let Some(interfaces) = cs.at(INTERFACES) else { return };
    let h = cs.hive();
    for key in h.subkeys(&interfaces) {
        let dhcp = h.value(&key, "EnableDHCP").and_then(|v| v.dword()) == Some(1);
        let mut addresses = list(h.value(&key, "IPAddress"));
        addresses.extend(list(h.value(&key, "DhcpIPAddress")));
        addresses.dedup();
        if addresses.is_empty() {
            continue;
        }
        let mut gateways = list(h.value(&key, "DefaultGateway"));
        gateways.extend(list(h.value(&key, "DhcpDefaultGateway")));
        gateways.dedup();
        let mut dns = list(h.value(&key, "NameServer"));
        dns.extend(list(h.value(&key, "DhcpNameServer")));
        dns.dedup();
        let (adapter, mac) = adapters.get(&key.name.to_ascii_uppercase()).cloned().unwrap_or_default();
        let record = NetworkInterfaceRecord {
            id: key.name.clone(),
            adapter,
            addresses,
            dhcp,
            gateways,
            dhcp_server: h.text(&key, "DhcpServer").filter(|s| s != "255.255.255.255"),
            dns,
            domain: h.text(&key, "Domain").or_else(|| h.text(&key, "DhcpDomain")),
            mac,
            lease_obtained: h.value(&key, "LeaseObtainedTime").and_then(|v| v.dword()).and_then(|s| Timestamp::from_unix_secs(i64::from(s))),
        };
        rec.record(keys::NETWORK_INTERFACE, &record);
    }
}

/// Interface GUID (upper case) → (adapter description, configured MAC override).
fn adapters(cs: &ControlSet<'_, '_>) -> HashMap<String, (Option<String>, Option<String>)> {
    let h = cs.hive();
    let Some(class) = cs.at(ADAPTERS) else { return HashMap::new() };
    h.subkeys(&class)
        .into_iter()
        .filter(|k| k.name.bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|k| {
            let guid = h.text(&k, "NetCfgInstanceId")?.to_ascii_uppercase();
            let mac = h.text(&k, "NetworkAddress").filter(|m| m.len() == 12).map(|m| {
                m.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).to_ascii_uppercase()).collect::<Vec<_>>().join(":")
            });
            Some((guid, (h.text(&k, "DriverDesc"), mac)))
        })
        .collect()
}
