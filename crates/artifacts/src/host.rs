//! Host facts: the keys parsers store machine details under, and the records some of them carry
//! as JSON (users, network interfaces and profiles, USB devices). The machines context reads
//! them back with the same types, so producer and consumer share one definition.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use strata_kernel::Timestamp;

/// Fact keys. Single values are plain text; `USER`, `NETWORK_*` and `USB_DEVICE` hold JSON records.
pub mod keys {
    pub const COMPUTER_NAME: &str = "computer_name";
    pub const WINDOWS_PRODUCT: &str = "windows_product";
    pub const WINDOWS_EDITION: &str = "windows_edition";
    pub const WINDOWS_VERSION: &str = "windows_version";
    pub const WINDOWS_BUILD: &str = "windows_build";
    pub const WINDOWS_SERVICE_PACK: &str = "windows_service_pack";
    pub const INSTALL_DATE: &str = "install_date";
    pub const SYSTEM_ROOT: &str = "system_root";
    pub const REGISTERED_OWNER: &str = "registered_owner";
    pub const REGISTERED_ORGANIZATION: &str = "registered_organization";
    pub const LINUX_DISTRO: &str = "linux_distro";
    pub const LINUX_DISTRO_ID: &str = "linux_distro_id";
    pub const LINUX_VERSION: &str = "linux_version";
    /// Zone name (`Russian Standard Time`, `Europe/Moscow`).
    pub const TIMEZONE: &str = "timezone";
    /// Minutes to add to local time to get UTC (Windows `Bias`: UTC+3 is -180).
    pub const TIMEZONE_BIAS: &str = "timezone_bias";
    pub const LAST_SHUTDOWN: &str = "last_shutdown";
    /// DNS domain or Windows domain the machine belonged to.
    pub const DOMAIN: &str = "domain";
    pub const USER: &str = "user";
    pub const NETWORK_INTERFACE: &str = "network_interface";
    pub const NETWORK_PROFILE: &str = "network_profile";
    pub const USB_DEVICE: &str = "usb_device";
    pub const CPU: &str = "hw_cpu";
    pub const VIDEO: &str = "hw_video";
    pub const SYSTEM_MODEL: &str = "hw_system";
    pub const DISK_DRIVE: &str = "hw_disk";
    /// NetBIOS name of the machine an LNK target lived on.
    pub const LNK_MACHINE: &str = "machine_id";
    pub const WALLET_DATA_DIR: &str = "wallet_data_dir";
}

/// A user account: SAM entry, profile folder or `/etc/passwd` line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserRecord {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Windows SID or `uid <n>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Profile folder or home directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub last_logon: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub password_set: Option<Timestamp>,
    /// Profile last loaded (ProfileList) — close to the last logon.
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub profile_loaded: Option<Timestamp>,
}

/// One network interface as configured (static or DHCP).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkInterfaceRecord {
    /// Interface GUID or Linux interface name.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    pub dhcp: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_server: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub lease_obtained: Option<Timestamp>,
}

/// A network the machine joined: Wi-Fi SSID, wired network or saved connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkProfileRecord {
    pub name: String,
    /// `wireless`, `wired`, `mobile broadband`, `vpn`...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub first_connected: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub last_connected: Option<Timestamp>,
    /// The times are the machine's local time, not UTC.
    pub local_time: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_suffix: Option<String>,
    /// MAC of the local interface the connection was bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// MAC of the Wi-Fi access point (XP wireless configuration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
}

/// A USB device seen by the system.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UsbRecord {
    pub name: String,
    /// `storage`, `hardware wallet`, `portable device`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub first_connected: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub last_connected: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none", with = "stamp")]
    pub last_removed: Option<Timestamp>,
    /// Only the registry key's last write is known (approximate).
    pub approximate: bool,
}

/// JSON text of a record, as stored in a fact value.
pub fn to_value<T: Serialize>(record: &T) -> String {
    serde_json::to_string(record).unwrap_or_default()
}

/// Read a record back from a fact value; `None` for plain text or another shape.
pub fn from_value<T: DeserializeOwned>(value: &str) -> Option<T> {
    value.trim_start().starts_with('{').then(|| serde_json::from_str(value).ok()).flatten()
}

/// Optional timestamps as readable `YYYY-MM-DD HH:MM:SS` text.
mod stamp {
    use serde::{Deserialize, Deserializer, Serializer};
    use strata_kernel::Timestamp;

    pub fn serialize<S: Serializer>(t: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&t.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        Ok(text.as_deref().and_then(Timestamp::parse_iso8601))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_as_readable_json() {
        let user = UserRecord { name: "Admin".into(), last_logon: Timestamp::from_unix_secs(1_300_000_000), logon_count: Some(7), ..Default::default() };
        let text = to_value(&user);
        assert!(text.contains("\"last_logon\":\"2011-03-13 07:06:40\""), "{text}");
        assert_eq!(from_value::<UserRecord>(&text), Some(user));
        assert_eq!(from_value::<UserRecord>("Admin"), None);
        assert_eq!(from_value::<UsbRecord>("{broken"), None);
    }
}
