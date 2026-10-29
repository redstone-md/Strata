//! Folds host facts, logons, activity and program events of one installation into a
//! [`MachineProfile`].

use super::users::{UserBook, logon_user};
use super::{Hardware, MachineProfile, Network, NetworkProfile, OsInfo, TimeZone, UsbDevice};
use crate::location::{InstallKey, InstallKind};
use crate::software::{ProgramRow, SoftwareBook};
use crate::values::{Provenance, Values, When};
use crate::FactRow;
use strata_artifacts::host::{NetworkProfileRecord, UsbRecord, UserRecord, from_value, keys};
use strata_kernel::Timestamp;

/// Every fact key a profile reads (the case query loads only these).
pub const PROFILE_KEYS: &[&str] = &[
    keys::COMPUTER_NAME,
    keys::WINDOWS_PRODUCT,
    keys::LINUX_DISTRO,
    keys::WINDOWS_EDITION,
    keys::WINDOWS_VERSION,
    keys::LINUX_VERSION,
    keys::WINDOWS_BUILD,
    keys::WINDOWS_SERVICE_PACK,
    keys::SYSTEM_ROOT,
    keys::INSTALL_DATE,
    keys::REGISTERED_OWNER,
    keys::REGISTERED_ORGANIZATION,
    keys::TIMEZONE,
    keys::TIMEZONE_BIAS,
    keys::LAST_SHUTDOWN,
    keys::DOMAIN,
    keys::NETWORK_INTERFACE,
    keys::NETWORK_PROFILE,
    keys::CPU,
    keys::VIDEO,
    keys::SYSTEM_MODEL,
    keys::DISK_DRIVE,
    keys::USB_DEVICE,
    keys::USER,
    OLD_PROFILE,
    keys::LNK_MACHINE,
    keys::WALLET_DATA_DIR,
];
/// `SID → path` profile facts of older cases.
const OLD_PROFILE: &str = "profile";

pub(crate) struct ProfileBuilder {
    key: InstallKey,
    kind: InstallKind,
    computer_name: Values<String>,
    os: OsInfo,
    owner: Values<String>,
    organization: Values<String>,
    time_zone: TimeZone,
    last_shutdown: Values<When>,
    network: Network,
    network_profiles: Vec<(NetworkProfileRecord, Provenance)>,
    hardware: Hardware,
    usb: Vec<(UsbRecord, Provenance)>,
    users: UserBook,
    software: SoftwareBook,
    lnk_machines: Values<String>,
    facts: usize,
}

impl ProfileBuilder {
    pub fn new(key: InstallKey, kind: InstallKind) -> Self {
        Self {
            key,
            kind,
            computer_name: Values::default(),
            os: OsInfo::default(),
            owner: Values::default(),
            organization: Values::default(),
            time_zone: TimeZone::default(),
            last_shutdown: Values::default(),
            network: Network::default(),
            network_profiles: Vec::new(),
            hardware: Hardware::default(),
            usb: Vec::new(),
            users: UserBook::default(),
            software: SoftwareBook::default(),
            lnk_machines: Values::default(),
            facts: 0,
        }
    }

    pub fn key(&self) -> &InstallKey {
        &self.key
    }

    pub fn fact(&mut self, f: &FactRow) {
        let src = Provenance::new(f.artifact.clone(), f.source.clone());
        let text = f.value.trim().to_string();
        let when = || Timestamp::parse_iso8601(&text).map(When);
        self.facts += 1;
        match f.key.as_str() {
            keys::COMPUTER_NAME => self.computer_name.add(text, src),
            keys::WINDOWS_PRODUCT | keys::LINUX_DISTRO => self.os.product.add(text, src),
            keys::WINDOWS_EDITION => self.os.edition.add(text, src),
            keys::WINDOWS_VERSION | keys::LINUX_VERSION => self.os.version.add(text, src),
            keys::WINDOWS_BUILD => self.os.build.add(text, src),
            keys::WINDOWS_SERVICE_PACK => self.os.service_pack.add(text, src),
            keys::SYSTEM_ROOT => self.os.system_root.add(text, src),
            keys::INSTALL_DATE => when().into_iter().for_each(|t| self.os.install_date.add(t, src.clone())),
            keys::REGISTERED_OWNER => self.owner.add(text, src),
            keys::REGISTERED_ORGANIZATION => self.organization.add(text, src),
            keys::TIMEZONE => self.time_zone(text, src),
            keys::TIMEZONE_BIAS => text.parse().into_iter().for_each(|b| self.time_zone.bias_minutes.add(b, src.clone())),
            keys::LAST_SHUTDOWN => when().into_iter().for_each(|t| self.last_shutdown.add(t, src.clone())),
            keys::DOMAIN => self.network.domain.add(text, src),
            keys::NETWORK_INTERFACE => from_value(&text).into_iter().for_each(|r| self.network.interfaces.add(r, src.clone())),
            keys::NETWORK_PROFILE => from_value(&text).into_iter().for_each(|r| self.network_profiles.push((r, src.clone()))),
            keys::CPU => self.hardware.cpu.add(text, src),
            keys::VIDEO => self.hardware.video.add(text, src),
            keys::SYSTEM_MODEL => self.hardware.system.add(text, src),
            keys::DISK_DRIVE => self.hardware.disks.add(text, src),
            keys::USB_DEVICE => self.usb.push((usb_record(&text), src)),
            keys::USER => self.users.record(from_value::<UserRecord>(&text).unwrap_or_else(|| old_profile(&text)), src),
            OLD_PROFILE => self.users.record(old_profile(&text), src),
            keys::LNK_MACHINE => self.lnk_machines.add(text, src),
            keys::WALLET_DATA_DIR => self.software.data_dir(&text, src),
            _ => self.facts -= 1,
        }
    }

    /// Old cases stored `Russian Standard Time (bias -180 min)` in one fact.
    fn time_zone(&mut self, text: String, src: Provenance) {
        if let Some((name, rest)) = text.rsplit_once(" (bias ")
            && let Some(Ok(bias)) = rest.strip_suffix(" min)").map(str::parse::<i32>)
        {
            self.time_zone.bias_minutes.add(bias, src.clone());
            if !name.trim().is_empty() {
                self.time_zone.name.add(name.trim().to_string(), src);
            }
            return;
        }
        self.time_zone.name.add(text, src);
    }

    /// Aggregated logon events of one title.
    pub fn logon(&mut self, title: &str, last: Timestamp, count: u64) {
        if let Some(user) = logon_user(title) {
            self.users.logon(&user, last, count);
        }
    }

    pub fn user_activity(&mut self, user: &str, last: Timestamp) {
        self.users.activity(user, last);
    }

    pub fn program(&mut self, row: &ProgramRow) {
        self.software.program(row);
    }

    pub fn finish(self) -> MachineProfile {
        let bias = self.time_zone.bias_minutes.value().copied();
        let names: Vec<String> = self.computer_name.iter().map(|n| n.value.to_lowercase()).collect();
        let mut linked = Values::default();
        for m in self.lnk_machines.iter().filter(|m| !names.contains(&m.value.to_lowercase())) {
            for s in &m.sources {
                linked.add(m.value.clone(), s.clone());
            }
        }
        let mut network = self.network;
        network.profiles = network_profiles(self.network_profiles, bias);
        MachineProfile {
            key: self.key,
            kind: self.kind,
            computer_name: self.computer_name,
            os: self.os,
            owner: self.owner,
            organization: self.organization,
            users: self.users.finish(),
            time_zone: self.time_zone,
            last_shutdown: self.last_shutdown,
            network,
            hardware: self.hardware,
            usb: usb_devices(self.usb),
            software: self.software.finish(),
            linked_machines: linked,
            facts: self.facts,
        }
    }
}

/// `S-1-5-21-…-1003 → C:\Users\Olga` (older cases).
fn old_profile(text: &str) -> UserRecord {
    let (sid, path) = text.split_once(" → ").unwrap_or(("", text));
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path).to_string();
    UserRecord { name, id: Some(sid.to_string()).filter(|s| !s.is_empty()), home: Some(path.to_string()), ..Default::default() }
}

/// JSON record, or the older `Kingston DataTraveler (serial 5B8A)` text.
fn usb_record(text: &str) -> UsbRecord {
    from_value(text).unwrap_or_else(|| {
        let (name, serial) = text.rsplit_once(" (serial ").map_or((text, None), |(n, s)| (n, Some(s.trim_end_matches(')').to_string())));
        UsbRecord { name: name.to_string(), kind: "storage".into(), serial, approximate: true, ..Default::default() }
    })
}

/// One entry per network name; local times moved to UTC when the bias is known.
fn network_profiles(records: Vec<(NetworkProfileRecord, Provenance)>, bias: Option<i32>) -> Vec<NetworkProfile> {
    let mut out: Vec<NetworkProfile> = Vec::new();
    for (r, src) in records {
        let to_utc = |t: Option<Timestamp>| match (t, bias) {
            (Some(t), Some(b)) if r.local_time => Timestamp::from_unix_secs(t.unix_secs() + i64::from(b) * 60),
            _ => t,
        };
        let (first, last) = (to_utc(r.first_connected), to_utc(r.last_connected));
        let local_time = r.local_time && bias.is_none();
        match out.iter_mut().find(|p| p.name.eq_ignore_ascii_case(&r.name)) {
            Some(p) => {
                p.first_connected = match (p.first_connected, first) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                p.last_connected = p.last_connected.max(last);
                p.gateway_mac = p.gateway_mac.take().or(r.gateway_mac);
                p.bssid = p.bssid.take().or(r.bssid);
                if !p.sources.contains(&src) && p.sources.len() < 4 {
                    p.sources.push(src);
                }
            }
            None => out.push(NetworkProfile {
                name: r.name,
                kind: r.kind,
                first_connected: first,
                last_connected: last,
                local_time,
                gateway_mac: r.gateway_mac,
                dns_suffix: r.dns_suffix,
                bssid: r.bssid,
                mac: r.mac,
                sources: vec![src],
            }),
        }
    }
    out.sort_by(|a, b| b.last_connected.cmp(&a.last_connected).then(a.name.cmp(&b.name)));
    out
}

/// One entry per (name, serial), widest time span.
fn usb_devices(records: Vec<(UsbRecord, Provenance)>) -> Vec<UsbDevice> {
    let mut out: Vec<UsbDevice> = Vec::new();
    for (r, src) in records {
        let first = r.first_connected.or(r.last_connected);
        let last = r.last_connected.max(r.last_removed);
        let same = |d: &&mut UsbDevice| d.name.eq_ignore_ascii_case(&r.name) && d.serial == r.serial;
        match out.iter_mut().find(same) {
            Some(d) => {
                d.first_connected = match (d.first_connected, first) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                d.last_connected = d.last_connected.max(last);
                d.approximate &= r.approximate;
                if !d.sources.contains(&src) && d.sources.len() < 4 {
                    d.sources.push(src);
                }
            }
            None => out.push(UsbDevice {
                name: r.name,
                kind: r.kind,
                serial: r.serial,
                first_connected: first,
                last_connected: last,
                approximate: r.approximate,
                sources: vec![src],
            }),
        }
    }
    // Hardware wallets first, then most recently connected.
    out.sort_by(|a, b| (a.kind != "hardware wallet").cmp(&(b.kind != "hardware wallet")).then(b.last_connected.cmp(&a.last_connected)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_key_is_read() {
        let key = InstallKey { volume: None, family: crate::OsFamily::Windows, root: String::new() };
        for k in PROFILE_KEYS {
            let mut b = ProfileBuilder::new(key.clone(), InstallKind::System);
            b.fact(&FactRow { volume: None, key: k.to_string(), value: "2011-01-01 00:00:00".into(), artifact: "t".into(), source: "x".into() });
            assert_eq!(b.facts, 1, "{k}");
        }
    }
}
