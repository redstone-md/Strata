//! Which installation a file belongs to, from its path inside a volume: the folder above the
//! first operating-system folder (`Windows`, `Users`, `etc`, `home`...) is the installation
//! root. `Windows.old/Windows/...` is the previous Windows, `var/lib/docker/.../diff/etc/...` a
//! container, `Backup/C/Windows/...` a copied system.

use serde::Serialize;
use std::fmt;

/// Top-level folders of a Windows installation (lower case).
const WINDOWS_MARKERS: &[&str] = &[
    "windows", "winnt", "documents and settings", "users", "program files", "program files (x86)", "programdata", "recycler",
    "$recycle.bin", "system volume information",
];
/// Top-level folders of a Linux installation.
const LINUX_MARKERS: &[&str] = &["etc", "home", "var", "usr", "root", "boot"];
/// Folders holding container root filesystems (`<marker>/<id>/<diff|merged|rootfs>`).
const CONTAINER_STORES: &[&str] = &["var/lib/docker/", "var/lib/containers/", "var/lib/lxc/", "var/lib/lxd/"];
const CONTAINER_ROOTS: &[&str] = &["diff", "merged", "rootfs"];
/// Profile folders that are not a person.
const NON_USERS: &[&str] = &["all users", "default user", "default", "public", "localservice", "networkservice", "lost+found"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum OsFamily {
    Windows,
    Linux,
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
        })
    }
}

/// How an installation sits on the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum InstallKind {
    /// At the volume root: the system that ran from this volume.
    System,
    /// `Windows.old`: the Windows replaced by an upgrade or reinstall.
    Previous,
    /// A copy of a system folder (backup, restored folder).
    Copy,
    /// A Docker / LXC / Podman container's filesystem.
    Container,
    /// A volume of home folders only (separate `/home` partition).
    HomeVolume,
}

/// One operating-system installation: volume, family and root folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct InstallKey {
    /// `None` in cases made before volumes were recorded.
    pub volume: Option<u32>,
    pub family: OsFamily,
    /// Folder above the system folders (`""` at the volume root).
    pub root: String,
}

/// Where a path puts its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub family: OsFamily,
    pub root: String,
    pub kind: InstallKind,
    /// Profile or home folder name the file lives under.
    pub user: Option<String>,
}

impl Location {
    /// `None` for files outside any recognisable system layout.
    pub fn of(path: &str) -> Option<Location> {
        let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
        let lower: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
        let found = lower.iter().enumerate().find_map(|(i, p)| {
            if WINDOWS_MARKERS.contains(&p.as_str()) {
                Some((i, OsFamily::Windows))
            } else if LINUX_MARKERS.contains(&p.as_str()) {
                Some((i, OsFamily::Linux))
            } else {
                None
            }
        });
        let Some((i, family)) = found else { return Self::home_volume(&parts) };
        let root = parts[..i].join("/");
        if family == OsFamily::Linux
            && let Some(inner) = Self::container(&parts, &lower, i)
        {
            return Some(inner);
        }
        let kind = match root.to_lowercase() {
            r if r.is_empty() => InstallKind::System,
            r if r.split('/').any(|p| p == "windows.old") => InstallKind::Previous,
            _ => InstallKind::Copy,
        };
        let user = matches!(lower[i].as_str(), "users" | "documents and settings" | "home")
            .then(|| parts.get(i + 1).filter(|_| i + 2 < parts.len()).map(|u| u.to_string()))
            .flatten()
            .filter(|u| !NON_USERS.contains(&u.to_lowercase().as_str()));
        Some(Location { family, root, kind, user })
    }

    /// `var/lib/docker/overlay2/<id>/diff/etc/...` → the container's own layout.
    fn container(parts: &[&str], lower: &[String], i: usize) -> Option<Location> {
        let joined = lower[i..].join("/");
        CONTAINER_STORES.iter().find(|s| joined.starts_with(*s))?;
        let j = (i..lower.len()).find(|&j| CONTAINER_ROOTS.contains(&lower[j].as_str()))?;
        let inner = Self::of(&parts[j + 1..].join("/")).filter(|l| l.family == OsFamily::Linux)?;
        let prefix = parts[..=j].join("/");
        let root = if inner.root.is_empty() { prefix } else { format!("{prefix}/{}", inner.root) };
        Some(Location { root, kind: InstallKind::Container, ..inner })
    }

    /// A separate `/home` partition: `<user>/.bash_history`, `<user>/.mozilla/...`.
    fn home_volume(parts: &[&str]) -> Option<Location> {
        let hidden = parts.get(1).is_some_and(|p| p.starts_with('.') && p.len() > 1);
        hidden.then(|| Location { family: OsFamily::Linux, root: String::new(), kind: InstallKind::HomeVolume, user: Some(parts[0].to_string()) })
    }

    pub fn key(&self, volume: Option<u32>) -> InstallKey {
        InstallKey { volume, family: self.family, root: self.root.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str) -> (OsFamily, String, InstallKind, Option<String>) {
        let l = Location::of(path).unwrap_or_else(|| panic!("{path} not located"));
        (l.family, l.root, l.kind, l.user)
    }

    #[test]
    fn roots_kinds_and_users() {
        use InstallKind::*;
        use OsFamily::*;
        assert_eq!(at("WINDOWS/system32/config/SYSTEM"), (Windows, "".into(), System, None));
        assert_eq!(at("Documents and Settings/Admin/NTUSER.DAT"), (Windows, "".into(), System, Some("Admin".into())));
        assert_eq!(at("Documents and Settings/All Users/x.lnk").3, None);
        assert_eq!(at("Users/Olga"), (Windows, "".into(), System, None), "a bare profile folder names no file in it");
        assert_eq!(at("Windows.old/Users/Olga/NTUSER.DAT"), (Windows, "Windows.old".into(), Previous, Some("Olga".into())));
        assert_eq!(at("Backup/C/WINDOWS/system32/config/SOFTWARE"), (Windows, "Backup/C".into(), Copy, None));
        assert_eq!(at("System Volume Information/_restore{1}/RP3/snapshot/_REGISTRY_MACHINE_SYSTEM").1, "");
        assert_eq!(at("etc/hostname"), (Linux, "".into(), System, None));
        assert_eq!(at("home/andrew/.bash_history"), (Linux, "".into(), System, Some("andrew".into())));
        let docker = at("var/lib/docker/overlay2/ab12/diff/etc/os-release");
        assert_eq!(docker, (Linux, "var/lib/docker/overlay2/ab12/diff".into(), Container, None));
        assert_eq!(at("var/lib/lxc/web/rootfs/home/www/.profile").3, Some("www".into()));
        assert_eq!(at("andrew/.mozilla/firefox/x/places.sqlite"), (Linux, "".into(), HomeVolume, Some("andrew".into())));
        assert_eq!(at("var/lib/docker/containers/abc/config.v2.json").1, "", "container metadata belongs to the host");
        assert!(Location::of("Photos/2010/img.jpg").is_none());
        assert!(Location::of("").is_none());
    }
}
