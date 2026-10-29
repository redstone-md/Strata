//! SYSTEM, SOFTWARE and SAM hives: host identity, USB devices, installed programs, profiles,
//! user accounts.

use super::hive::{Hive, Key};
use crate::results::{IdentityKind, Recorder};
use crate::text::{filetime_at, parse_iso8601, utf16_at};
use strata_kernel::Timestamp;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_timeline::EventKind;

/// Device property set holding install / arrival / removal FILETIMEs (Win7+).
const DEVICE_TIMES: &str = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}";

pub(crate) struct SystemHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> SystemHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    fn control_set(&self) -> Option<Key> {
        let current = self.hive.open("Select").and_then(|k| self.hive.value(&k, "Current")).and_then(|v| v.dword());
        current
            .and_then(|n| self.hive.open(&format!("ControlSet{n:03}")))
            .or_else(|| self.hive.open("ControlSet001"))
            .or_else(|| self.hive.open("CurrentControlSet"))
    }

    pub fn parse(&self, rec: &mut Recorder) {
        let Some(cs) = self.control_set() else { return };
        let h = self.hive;
        let at = |path: &str| path.split('\\').try_fold(cs.clone(), |k, p| h.subkey(&k, p));
        if let Some(name) = at("Control\\ComputerName\\ComputerName").and_then(|k| h.value(&k, "ComputerName")).and_then(|v| v.string()) {
            rec.fact("computer_name", name);
        }
        if let Some(tz) = at("Control\\TimeZoneInformation") {
            let name = h.value(&tz, "TimeZoneKeyName").or_else(|| h.value(&tz, "StandardName")).and_then(|v| v.string());
            let bias = h.value(&tz, "Bias").and_then(|v| v.dword()).map(|b| b as i32);
            rec.fact("timezone", format!("{} (bias {} min)", name.unwrap_or_default(), bias.unwrap_or(0)));
        }
        if let Some(t) = at("Control\\Windows").and_then(|k| h.value(&k, "ShutdownTime")).and_then(|v| filetime_at(&v.data, 0)) {
            rec.emit(Some(t), EventKind::Other, "System shutdown", "SYSTEM Control\\Windows ShutdownTime");
        }
        if let Some(usbstor) = at("Enum\\USBSTOR") {
            for device in h.subkeys(&usbstor) {
                for instance in h.subkeys(&device) {
                    self.usb_device(rec, &device, &instance);
                }
            }
        }
        self.mounted_devices(rec);
    }

    fn usb_device(&self, rec: &mut Recorder, device: &Key, instance: &Key) {
        let h = self.hive;
        let friendly = h.value(instance, "FriendlyName").and_then(|v| v.string()).unwrap_or_else(|| device.name.clone());
        let serial = instance.name.split('&').next().unwrap_or(&instance.name).to_string();
        let detail = format!("USBSTOR {}; serial {serial}", device.name);
        rec.fact("usb_device", format!("{friendly} (serial {serial})"));
        let times = DEVICE_TIMES.split('\\').try_fold(instance.clone(), |k, p| h.subkey(&k, p));
        let prop = |id: &str| {
            let k = times.as_ref().and_then(|t| h.subkey(t, id)).and_then(|k| h.subkey(&k, "00000000"))?;
            h.values(&k).into_iter().find_map(|v| filetime_at(&v.data, 0))
        };
        let mut any = false;
        for (id, what) in [("0064", "first install"), ("0066", "last connected"), ("0067", "last removed")] {
            if let Some(t) = prop(id) {
                rec.emit(Some(t), EventKind::UsbDevice, friendly.clone(), format!("{detail}; {what}"));
                any = true;
            }
        }
        if !any {
            rec.emit(instance.last_write, EventKind::UsbDevice, friendly, format!("{detail}; key last write"));
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

pub(crate) struct SoftwareHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> SoftwareHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    pub fn parse(&self, rec: &mut Recorder) {
        let h = self.hive;
        if let Some(nt) = h.open("Microsoft\\Windows NT\\CurrentVersion") {
            for (value, fact) in [("ProductName", "windows_product"), ("CSDVersion", "windows_service_pack"), ("RegisteredOwner", "registered_owner"), ("RegisteredOrganization", "registered_organization")] {
                if let Some(s) = h.value(&nt, value).and_then(|v| v.string()) {
                    rec.fact(fact, s);
                }
            }
            let installed = h.value(&nt, "InstallDate").and_then(|v| v.dword()).and_then(|s| Timestamp::from_unix_secs(i64::from(s)));
            let product = h.value(&nt, "ProductName").and_then(|v| v.string()).unwrap_or_else(|| "Windows".into());
            rec.dated(installed, EventKind::ProgramInstalled, format!("{product} installed"), "SOFTWARE InstallDate");
        }
        if let Some(profiles) = h.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList") {
            for sid in h.subkeys(&profiles) {
                let Some(path) = h.value(&sid, "ProfileImagePath").and_then(|v| v.string()) else { continue };
                rec.fact("profile", format!("{} → {path}", sid.name));
                let user = path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
                if sid.name.starts_with("S-1-5-21-") {
                    rec.identity(IdentityKind::Login, &user, Some("Windows"), sid.last_write);
                }
            }
        }
        for base in ["Microsoft\\Windows\\CurrentVersion\\Uninstall", "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"] {
            let Some(un) = h.open(base) else { continue };
            for app in h.subkeys(&un) {
                self.program(rec, &app);
            }
        }
        if let Some(run) = h.open("Microsoft\\Windows\\CurrentVersion\\Run") {
            for v in h.values(&run) {
                rec.fact("autorun", format!("{} = {}", v.name, v.display()));
            }
        }
    }

    fn program(&self, rec: &mut Recorder, app: &Key) {
        let h = self.hive;
        let Some(name) = h.value(app, "DisplayName").and_then(|v| v.string()) else { return };
        let get = |n: &str| h.value(app, n).map(|v| v.display()).unwrap_or_default();
        let detail = format!("version {}; publisher {}; location {}", get("DisplayVersion"), get("Publisher"), get("InstallLocation"));
        match h.value(app, "InstallDate").and_then(|v| v.string()).and_then(|d| parse_iso8601(&d)) {
            Some(t) => rec.emit(Some(t), EventKind::ProgramInstalled, name, detail),
            None => rec.push_low(app.last_write, EventKind::ProgramInstalled, name, format!("{detail}; key last write")),
        }
    }
}

pub(crate) struct SamHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> SamHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    /// User names (`Names\<name>`, RID in the default value's type) and the `F` value of
    /// `Users\<RID>`: last logon @8, password set @24, last failed @40, logon count @66.
    pub fn parse(&self, rec: &mut Recorder) {
        let h = self.hive;
        let Some(names) = h.open("SAM\\Domains\\Account\\Users\\Names") else { return };
        let users = h.open("SAM\\Domains\\Account\\Users");
        for n in h.subkeys(&names) {
            let rid = h.values(&n).into_iter().find(|v| v.name.is_empty()).map(|v| v.kind);
            rec.identity(IdentityKind::Login, &n.name, Some("Windows"), n.last_write);
            let f = rid.and_then(|rid| users.as_ref().and_then(|u| h.subkey(u, &format!("{rid:08X}")))).and_then(|k| h.value(&k, "F"));
            let Some(f) = f else { continue };
            let count = u16_le(&f.data, 66).unwrap_or(0);
            let rid = u32_le(&f.data, 48).unwrap_or(0);
            rec.dated(filetime_at(&f.data, 8), EventKind::Login, format!("Windows logon: {}", n.name), format!("RID {rid}; logon count {count}"));
            rec.dated(filetime_at(&f.data, 24), EventKind::Other, format!("Password set: {}", n.name), "SAM F value");
            rec.dated(filetime_at(&f.data, 40), EventKind::Other, format!("Failed logon: {}", n.name), "SAM F value");
        }
    }
}
