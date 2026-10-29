//! SYSTEM hive: computer name, time zone, last shutdown, network configuration, hardware, USB
//! devices and drive letters.

mod hardware;
mod network;
mod usb;

use super::hive::{Hive, Key, Value};
use crate::host::keys;
use crate::results::Recorder;
use crate::text::{filetime_at, utf16_at};
use strata_timeline::EventKind;

pub(crate) struct SystemHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

/// The current control set, navigated by `\`-separated paths below it.
pub(super) struct ControlSet<'h, 'a> {
    hive: &'h Hive<'a>,
    root: Key,
}

impl<'h, 'a> ControlSet<'h, 'a> {
    pub fn hive(&self) -> &'h Hive<'a> {
        self.hive
    }

    pub fn at(&self, path: &str) -> Option<Key> {
        path.split('\\').filter(|p| !p.is_empty()).try_fold(self.root.clone(), |k, p| self.hive.subkey(&k, p))
    }

    /// String value at `path` (`None` when the key, value or text is missing).
    pub fn text(&self, path: &str, value: &str) -> Option<String> {
        self.at(path).and_then(|k| self.hive.text(&k, value))
    }
}

/// REG_SZ or REG_MULTI_SZ value as a list, split on spaces and commas (name server lists).
pub(super) fn list(value: Option<Value>) -> Vec<String> {
    let Some(v) = value else { return Vec::new() };
    let items = if v.kind == super::hive::REG_MULTI_SZ { v.multi_string() } else { v.string().into_iter().collect() };
    items
        .iter()
        .flat_map(|s| s.split([' ', ',', ';']))
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "0.0.0.0")
        .map(str::to_string)
        .collect()
}

impl<'h, 'a> SystemHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    fn control_set(&self) -> Option<ControlSet<'h, 'a>> {
        let h = self.hive;
        let current = h.open("Select").and_then(|k| h.value(&k, "Current")).and_then(|v| v.dword());
        let root = current
            .and_then(|n| h.open(&format!("ControlSet{n:03}")))
            .or_else(|| h.open("ControlSet001"))
            .or_else(|| h.open("CurrentControlSet"))?;
        Some(ControlSet { hive: h, root })
    }

    pub fn parse(&self, rec: &mut Recorder) {
        let Some(cs) = self.control_set() else { return };
        Self::identity(&cs, rec);
        Self::time_zone(&cs, rec);
        if let Some(t) = cs.at("Control\\Windows").and_then(|k| self.hive.value(&k, "ShutdownTime")).and_then(|v| filetime_at(&v.data, 0)) {
            rec.emit(Some(t), EventKind::Other, "System shutdown", "SYSTEM Control\\Windows ShutdownTime");
            rec.fact(keys::LAST_SHUTDOWN, t.to_string());
        }
        network::parse(&cs, rec);
        hardware::parse(&cs, rec);
        usb::parse(&cs, rec);
        self.mounted_devices(rec);
    }

    fn identity(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
        let tcpip = "Services\\Tcpip\\Parameters";
        let name = cs.text("Control\\ComputerName\\ComputerName", "ComputerName").or_else(|| cs.text(tcpip, "Hostname"));
        if let Some(name) = name {
            rec.fact(keys::COMPUTER_NAME, name);
        }
        if let Some(domain) = cs.text(tcpip, "Domain").or_else(|| cs.text(tcpip, "NV Domain")) {
            rec.fact(keys::DOMAIN, domain);
        }
    }

    /// Zone name and `Bias` (minutes, UTC = local + bias).
    fn time_zone(cs: &ControlSet<'_, '_>, rec: &mut Recorder) {
        let Some(tz) = cs.at("Control\\TimeZoneInformation") else { return };
        let h = cs.hive();
        if let Some(name) = h.text(&tz, "TimeZoneKeyName").or_else(|| h.text(&tz, "StandardName")) {
            rec.fact(keys::TIMEZONE, name);
        }
        if let Some(bias) = h.value(&tz, "Bias").and_then(|v| v.dword()) {
            rec.fact(keys::TIMEZONE_BIAS, (bias as i32).to_string());
        }
    }

    fn mounted_devices(&self, rec: &mut Recorder) {
        let Some(key) = self.hive.open("MountedDevices") else { return };
        for v in self.hive.values(&key).iter().filter(|v| v.name.starts_with("\\DosDevices\\")) {
            let text = utf16_at(&v.data, 0, v.data.len());
            if text.contains('#') {
                rec.fact("mounted_device", format!("{} → {text}", v.name.trim_start_matches("\\DosDevices\\")));
            }
        }
    }
}
