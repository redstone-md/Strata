//! What one installation says about the computer it ran on: identity, operating system,
//! owner, users, time zone, network, hardware, USB devices and crypto software. Every value
//! keeps the files it was read from.

mod builder;
mod users;

pub(crate) use builder::ProfileBuilder;
pub use users::UserAccount;

use crate::location::{InstallKey, InstallKind, OsFamily};
use crate::software::CryptoSoftware;
use crate::values::{SameValue, SourceRef, Sourced, Values, When};
use serde::Serialize;
use strata_artifacts::host::{NetworkInterfaceRecord, stamp};
use strata_kernel::Timestamp;

#[derive(Debug, Clone, Default, Serialize)]
pub struct OsInfo {
    /// `Microsoft Windows XP`, `Windows 7 Ultimate`, `Ubuntu 12.04.5 LTS`.
    pub product: Values<String>,
    pub edition: Values<String>,
    pub version: Values<String>,
    pub build: Values<String>,
    pub service_pack: Values<String>,
    pub install_date: Values<When>,
    /// `C:\WINDOWS` — names the drive letter the system had.
    pub system_root: Values<String>,
}

impl OsInfo {
    /// `Microsoft Windows XP Professional, Service Pack 3 (5.1, build 2600)`.
    pub fn label(&self) -> Option<String> {
        let mut text = self.product.value()?.clone();
        if let Some(sp) = self.service_pack.value() {
            text.push_str(&format!(", {sp}"));
        }
        let numbers: Vec<String> = [self.version.value().cloned(), self.build.value().map(|b| format!("build {b}"))].into_iter().flatten().collect();
        if !numbers.is_empty() {
            text.push_str(&format!(" ({})", numbers.join(", ")));
        }
        Some(text)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TimeZone {
    pub name: Values<String>,
    /// Minutes to add to local time for UTC (UTC+3 is -180).
    pub bias_minutes: Values<i32>,
}

impl TimeZone {
    /// `Russian Standard Time (UTC+03:00)`.
    pub fn label(&self) -> Option<String> {
        let offset = self.bias_minutes.value().map(|b| utc_offset(*b));
        match (self.name.value(), offset) {
            (Some(n), Some(o)) => Some(format!("{n} ({o})")),
            (Some(n), None) => Some(n.clone()),
            (None, o) => o,
        }
    }
}

/// `-180` → `UTC+03:00`.
pub fn utc_offset(bias_minutes: i32) -> String {
    let east = -bias_minutes;
    let sign = if east < 0 { '-' } else { '+' };
    format!("UTC{sign}{:02}:{:02}", east.abs() / 60, east.abs() % 60)
}

impl SameValue for NetworkInterfaceRecord {
    fn same(&self, other: &Self) -> bool {
        self.id.eq_ignore_ascii_case(&other.id) && self.addresses == other.addresses
    }
}

/// A network the machine joined, its times in UTC when the time zone was known.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkProfile {
    pub name: String,
    pub kind: Option<String>,
    #[serde(serialize_with = "stamp::serialize")]
    pub first_connected: Option<Timestamp>,
    #[serde(serialize_with = "stamp::serialize")]
    pub last_connected: Option<Timestamp>,
    /// Times are still the machine's local time (no time zone found).
    pub local_time: bool,
    pub gateway_mac: Option<String>,
    pub dns_suffix: Option<String>,
    pub bssid: Option<String>,
    pub mac: Option<String>,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Network {
    pub domain: Values<String>,
    pub interfaces: Values<NetworkInterfaceRecord>,
    pub profiles: Vec<NetworkProfile>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Hardware {
    pub cpu: Values<String>,
    pub video: Values<String>,
    /// Board / system model and BIOS.
    pub system: Values<String>,
    pub disks: Values<String>,
}

impl Hardware {
    pub fn is_empty(&self) -> bool {
        self.cpu.is_empty() && self.video.is_empty() && self.system.is_empty() && self.disks.is_empty()
    }
}

/// A USB device seen by this installation.
#[derive(Debug, Clone, Serialize)]
pub struct UsbDevice {
    pub name: String,
    pub kind: String,
    pub serial: Option<String>,
    #[serde(serialize_with = "stamp::serialize")]
    pub first_connected: Option<Timestamp>,
    #[serde(serialize_with = "stamp::serialize")]
    pub last_connected: Option<Timestamp>,
    pub approximate: bool,
    pub sources: Vec<SourceRef>,
}

/// One operating-system installation.
#[derive(Debug, Clone, Serialize)]
pub struct MachineProfile {
    pub key: InstallKey,
    pub kind: InstallKind,
    pub computer_name: Values<String>,
    pub os: OsInfo,
    pub owner: Values<String>,
    pub organization: Values<String>,
    pub users: Vec<UserAccount>,
    pub time_zone: TimeZone,
    pub last_shutdown: Values<When>,
    pub network: Network,
    pub hardware: Hardware,
    pub usb: Vec<UsbDevice>,
    pub software: Vec<CryptoSoftware>,
    /// Other computers named in LNK files (shares, copied links): not this machine.
    pub linked_machines: Values<String>,
    /// Facts read for this installation.
    pub facts: usize,
}

impl MachineProfile {
    pub fn family(&self) -> OsFamily {
        self.key.family
    }

    /// Computer name, else the OS and where it sits (`Windows on volume 2`).
    pub fn label(&self) -> String {
        if let Some(name) = self.computer_name.value() {
            return name.clone();
        }
        let os = self.os.product.value().cloned().unwrap_or_else(|| self.key.family.to_string());
        self.place().map_or(os.clone(), |p| format!("{os} {p}"))
    }

    /// `on volume 2`, `in Windows.old`, `container var/lib/docker/...`.
    pub fn place(&self) -> Option<String> {
        let volume = self.key.volume.map(|v| format!("volume {v}"));
        let root = (!self.key.root.is_empty()).then(|| self.key.root.clone());
        match (root, volume) {
            (Some(r), Some(v)) => Some(format!("in {r} on {v}")),
            (Some(r), None) => Some(format!("in {r}")),
            (None, Some(v)) => Some(format!("on {v}")),
            (None, None) => None,
        }
    }

    /// Last shutdown recorded by the system.
    pub fn last_shutdown(&self) -> Option<Timestamp> {
        self.last_shutdown.iter().map(|s| s.value.0).max()
    }

    /// People: accounts that logged on, have a profile folder or show activity.
    pub fn people(&self) -> impl Iterator<Item = &UserAccount> {
        self.users.iter().filter(|u| !u.builtin || u.logon_count.unwrap_or(0) > 0 || u.last_activity.is_some())
    }
}

/// First source of a list of sourced values, for hints.
pub fn first_source<T>(values: &Values<T>) -> Option<&SourceRef> {
    values.primary().and_then(Sourced::source)
}
