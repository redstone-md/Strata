//! SOFTWARE hive: Windows edition and install date, owner, user profiles, installed programs,
//! autoruns and the networks the machine joined.

mod networks;

use super::hive::{Hive, Key};
use crate::host::{UserRecord, keys};
use crate::results::{IdentityKind, Recorder};
use crate::text::parse_iso8601;
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

const CURRENT_VERSION: &str = "Microsoft\\Windows NT\\CurrentVersion";

/// `CurrentVersion` values stored as plain facts.
const VERSION_FACTS: &[(&str, &str)] = &[
    ("ProductName", keys::WINDOWS_PRODUCT),
    ("EditionID", keys::WINDOWS_EDITION),
    ("CSDVersion", keys::WINDOWS_SERVICE_PACK),
    ("RegisteredOwner", keys::REGISTERED_OWNER),
    ("RegisteredOrganization", keys::REGISTERED_ORGANIZATION),
    ("SystemRoot", keys::SYSTEM_ROOT),
];

pub(crate) struct SoftwareHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> SoftwareHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    pub fn parse(&self, rec: &mut Recorder) {
        let h = self.hive;
        if let Some(nt) = h.open(CURRENT_VERSION) {
            self.version(rec, &nt);
        }
        self.profiles(rec);
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
        networks::parse(h, rec);
    }

    fn version(&self, rec: &mut Recorder, nt: &Key) {
        let h = self.hive;
        for (value, fact) in VERSION_FACTS {
            if let Some(s) = h.text(nt, value) {
                rec.fact(fact, s);
            }
        }
        // Windows 10 reports `6.3` in CurrentVersion; the release id says more.
        let version = h.text(nt, "DisplayVersion").or_else(|| h.text(nt, "ReleaseId")).or_else(|| h.text(nt, "CurrentVersion"));
        rec.fact(keys::WINDOWS_VERSION, version.unwrap_or_default());
        rec.fact(keys::WINDOWS_BUILD, h.text(nt, "CurrentBuildNumber").or_else(|| h.text(nt, "CurrentBuild")).unwrap_or_default());
        let installed = h.value(nt, "InstallDate").and_then(|v| v.dword()).and_then(|s| Timestamp::from_unix_secs(i64::from(s)));
        let product = h.text(nt, "ProductName").unwrap_or_else(|| "Windows".into());
        rec.dated(installed, EventKind::ProgramInstalled, format!("{product} installed"), "SOFTWARE InstallDate");
        if let Some(t) = installed {
            rec.fact(keys::INSTALL_DATE, t.to_string());
        }
    }

    /// `ProfileList\<SID>`: profile folder, and when Vista+ last loaded it.
    fn profiles(&self, rec: &mut Recorder) {
        let h = self.hive;
        let Some(profiles) = h.open(&format!("{CURRENT_VERSION}\\ProfileList")) else { return };
        for sid in h.subkeys(&profiles) {
            let Some(path) = h.text(&sid, "ProfileImagePath") else { continue };
            if !sid.name.starts_with("S-1-5-21-") {
                continue;
            }
            let name = path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
            rec.identity(IdentityKind::Login, &name, Some("Windows"), sid.last_write);
            let dword = |n: &str| h.value(&sid, n).and_then(|v| v.dword()).map(u64::from);
            let loaded = match (dword("ProfileLoadTimeHigh"), dword("ProfileLoadTimeLow")) {
                (Some(hi), Some(lo)) => Timestamp::from_filetime(hi << 32 | lo),
                _ => None,
            };
            let user = UserRecord { name, id: Some(sid.name.clone()), home: Some(path), profile_loaded: loaded, ..Default::default() };
            rec.record(keys::USER, &user);
        }
    }

    fn program(&self, rec: &mut Recorder, app: &Key) {
        let h = self.hive;
        let Some(name) = h.text(app, "DisplayName") else { return };
        let get = |n: &str| h.value(app, n).map(|v| v.display()).unwrap_or_default();
        let detail = format!("version {}; publisher {}; location {}", get("DisplayVersion"), get("Publisher"), get("InstallLocation"));
        match h.value(app, "InstallDate").and_then(|v| v.string()).and_then(|d| parse_iso8601(&d)) {
            Some(t) => rec.emit(Some(t), EventKind::ProgramInstalled, name, detail),
            None => rec.push_low(app.last_write, EventKind::ProgramInstalled, name, format!("{detail}; key last write")),
        }
    }
}
