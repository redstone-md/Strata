//! Linux system configuration: host name, distribution (`os-release`, `lsb-release`,
//! `*-release`), time zone (`/etc/timezone`, the TZif footer of `/etc/localtime`), people
//! from `/etc/passwd`, NetworkManager saved connections and DHCP leases.

use crate::host::{NetworkInterfaceRecord, NetworkProfileRecord, UserRecord, keys};
use crate::results::Recorder;
use strata_kernel::Timestamp;

/// First uid of a person on Debian-like (1000) and old Red Hat (500) systems.
const FIRST_PERSON_UID: u32 = 500;
/// `nobody` and above.
const NOBODY_UID: u32 = 65_534;

/// Which system file a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemFile {
    Hostname,
    OsRelease,
    LsbRelease,
    /// `/etc/redhat-release` and friends: one line naming the distribution.
    ReleaseLine,
    Timezone,
    Localtime,
    SysconfigClock,
    Passwd,
    NmConnection,
    DhcpLease,
}

impl SystemFile {
    /// Classify a `/`-prefixed lowercase path.
    fn of(p: &str) -> Option<Self> {
        let name = p.rsplit('/').next().unwrap_or("");
        Some(match () {
            _ if p.ends_with("/etc/hostname") => Self::Hostname,
            _ if p.ends_with("/etc/os-release") || p.ends_with("/usr/lib/os-release") => Self::OsRelease,
            _ if p.ends_with("/etc/lsb-release") => Self::LsbRelease,
            _ if p.contains("/etc/") && ["redhat-release", "centos-release", "fedora-release", "suse-release"].contains(&name) => Self::ReleaseLine,
            _ if p.ends_with("/etc/timezone") => Self::Timezone,
            _ if p.ends_with("/etc/localtime") => Self::Localtime,
            _ if p.ends_with("/etc/sysconfig/clock") => Self::SysconfigClock,
            _ if p.ends_with("/etc/passwd") => Self::Passwd,
            _ if p.contains("/etc/networkmanager/system-connections/") => Self::NmConnection,
            _ if (p.contains("/var/lib/dhcp") || p.contains("/var/lib/networkmanager/")) && (name.ends_with(".leases") || name.ends_with(".lease")) => {
                Self::DhcpLease
            }
            _ => return None,
        })
    }
}

pub(crate) struct LinuxSystem;

impl LinuxSystem {
    /// Whether `path` (any case, `/` or `\`) is a system file this parser reads.
    pub fn matches(path: &str) -> bool {
        SystemFile::of(&normal(path)).is_some()
    }

    pub fn parse(path: &str, data: &[u8], rec: &mut Recorder) {
        let Some(file) = SystemFile::of(&normal(path)) else { return };
        let text = String::from_utf8_lossy(data);
        match file {
            SystemFile::Hostname => rec.fact(keys::COMPUTER_NAME, first_line(&text)),
            SystemFile::OsRelease => Self::release(&text, rec, ["PRETTY_NAME", "ID", "VERSION_ID"]),
            SystemFile::LsbRelease => Self::release(&text, rec, ["DISTRIB_DESCRIPTION", "DISTRIB_ID", "DISTRIB_RELEASE"]),
            SystemFile::ReleaseLine => rec.fact(keys::LINUX_DISTRO, first_line(&text)),
            SystemFile::Timezone => rec.fact(keys::TIMEZONE, first_line(&text)),
            SystemFile::SysconfigClock => rec.fact(keys::TIMEZONE, assignments(&text).find(|(k, _)| *k == "ZONE").map(|(_, v)| v).unwrap_or_default()),
            SystemFile::Localtime => Self::localtime(data, rec),
            SystemFile::Passwd => Self::passwd(&text, rec),
            SystemFile::NmConnection => Self::nm_connection(&text, rec),
            SystemFile::DhcpLease => Self::leases(&text, rec),
        }
    }

    fn release(text: &str, rec: &mut Recorder, [name, id, version]: [&str; 3]) {
        for (k, v) in assignments(text) {
            let key = match k {
                k if k == name => keys::LINUX_DISTRO,
                k if k == id => keys::LINUX_DISTRO_ID,
                k if k == version => keys::LINUX_VERSION,
                _ => continue,
            };
            rec.fact(key, v);
        }
    }

    /// TZif v2+ ends with a POSIX TZ string (`\nMSK-3\n`): its offset is minutes west of UTC,
    /// the same sign as a Windows bias.
    fn localtime(data: &[u8], rec: &mut Recorder) {
        if !data.starts_with(b"TZif") {
            return;
        }
        let text = String::from_utf8_lossy(data.get(data.len().saturating_sub(64)..).unwrap_or_default()).into_owned();
        let Some(footer) = text.trim_end_matches('\n').rsplit('\n').next().filter(|f| !f.is_empty() && f.is_ascii()) else { return };
        if let Some((name, bias)) = posix_tz(footer) {
            rec.fact(keys::TIMEZONE, name);
            rec.fact(keys::TIMEZONE_BIAS, bias.to_string());
        }
    }

    fn passwd(text: &str, rec: &mut Recorder) {
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            let (Some(name), Some(uid)) = (f.first(), f.get(2).and_then(|u| u.parse::<u32>().ok())) else { continue };
            let shell = f.get(6).copied().unwrap_or_default();
            if !(FIRST_PERSON_UID..NOBODY_UID).contains(&uid) || shell.ends_with("nologin") || shell.ends_with("/false") {
                continue;
            }
            let gecos = f.get(4).and_then(|g| g.split(',').next()).map(str::trim).filter(|g| !g.is_empty());
            let user = UserRecord {
                name: name.to_string(),
                full_name: gecos.map(str::to_string),
                id: Some(format!("uid {uid}")),
                home: f.get(5).map(|h| h.to_string()).filter(|h| !h.is_empty()),
                shell: Some(shell.to_string()).filter(|s| !s.is_empty()),
                ..Default::default()
            };
            rec.record(keys::USER, &user);
        }
    }

    /// Keyfile: `[connection] id= type= timestamp=`, `[wifi] ssid= mac-address=`.
    fn nm_connection(text: &str, rec: &mut Recorder) {
        let (mut profile, mut section, mut wifi) = (NetworkProfileRecord::default(), String::new(), None);
        for line in text.lines().map(str::trim) {
            if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = s.to_ascii_lowercase();
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let (k, v) = (k.trim(), v.trim());
            match (section.as_str(), k) {
                ("connection", "id") => profile.name = v.to_string(),
                ("connection", "type") => profile.kind = Some(connection_kind(v).to_string()),
                ("connection", "timestamp") => profile.last_connected = v.parse().ok().and_then(Timestamp::from_unix_secs),
                ("wifi" | "802-11-wireless", "ssid") => wifi = Some(ssid(v)),
                ("wifi" | "802-11-wireless" | "ethernet" | "802-3-ethernet", "mac-address") => profile.mac = Some(v.to_ascii_uppercase()),
                _ => {}
            }
        }
        match wifi {
            Some(ssid) if profile.name.is_empty() || profile.name == ssid => profile.name = ssid,
            Some(ssid) => profile.name = format!("{} (SSID {ssid})", profile.name),
            None => {}
        }
        if !profile.name.is_empty() {
            rec.record(keys::NETWORK_PROFILE, &profile);
        }
    }

    /// dhclient lease blocks: interface, fixed-address, routers, DNS servers, DHCP server.
    fn leases(text: &str, rec: &mut Recorder) {
        let mut seen: Vec<NetworkInterfaceRecord> = Vec::new();
        for block in text.split("lease {").skip(1) {
            let block = block.split('}').next().unwrap_or_default();
            let mut lease = NetworkInterfaceRecord { dhcp: true, ..Default::default() };
            for stmt in block.split(';').map(str::trim) {
                let (head, rest) = stmt.split_once(char::is_whitespace).unwrap_or((stmt, ""));
                let rest = rest.trim().trim_matches('"');
                match head {
                    "interface" => lease.id = rest.to_string(),
                    "fixed-address" => lease.addresses = vec![rest.to_string()],
                    "option" => {
                        let (opt, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                        let items = || value.split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
                        match opt {
                            "routers" => lease.gateways = items(),
                            "domain-name-servers" => lease.dns = items(),
                            "dhcp-server-identifier" => lease.dhcp_server = items().into_iter().next(),
                            "domain-name" => lease.domain = items().into_iter().next(),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            if !lease.addresses.is_empty() && !seen.contains(&lease) {
                rec.record(keys::NETWORK_INTERFACE, &lease);
                seen.push(lease);
            }
        }
    }
}

fn normal(path: &str) -> String {
    format!("/{}", path.to_lowercase().replace('\\', "/"))
}

fn first_line(text: &str) -> String {
    text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or_default().to_string()
}

/// `KEY=value` / `KEY="value"` lines.
fn assignments(text: &str) -> impl Iterator<Item = (&str, String)> {
    text.lines().filter_map(|l| {
        let (k, v) = l.trim().split_once('=')?;
        let v = v.trim().trim_matches(['"', '\'']).to_string();
        (!k.starts_with('#') && !v.is_empty()).then_some((k.trim(), v))
    })
}

fn connection_kind(t: &str) -> &'static str {
    match t {
        "wifi" | "802-11-wireless" => "wireless",
        "ethernet" | "802-3-ethernet" => "wired",
        "gsm" | "cdma" => "mobile broadband",
        "vpn" | "wireguard" => "vpn",
        _ => "other",
    }
}

/// SSID as text; old NetworkManager wrote it as `84;101;115;116;` byte lists.
fn ssid(v: &str) -> String {
    let bytes: Option<Vec<u8>> = v.trim_end_matches(';').split(';').map(|b| b.trim().parse::<u8>().ok()).collect();
    match bytes {
        Some(b) if v.contains(';') && !b.is_empty() => String::from_utf8_lossy(&b).into_owned(),
        _ => v.to_string(),
    }
}

/// `MSK-3`, `<+03>-3`, `EST5EDT,M3.2.0,M11.1.0`, `IST-5:30` → (name, minutes west of UTC).
fn posix_tz(s: &str) -> Option<(String, i32)> {
    let (name, rest) = match s.strip_prefix('<') {
        Some(r) => {
            let (n, rest) = r.split_once('>')?;
            (n.to_string(), rest)
        }
        None => {
            let end = s.find(|c: char| !c.is_ascii_alphabetic())?;
            (s[..end].to_string(), &s[end..])
        }
    };
    let digits_end = rest.find(|c: char| !(c.is_ascii_digit() || matches!(c, '+' | '-' | ':'))).unwrap_or(rest.len());
    let offset = &rest[..digits_end];
    let (sign, body) = match offset.strip_prefix('-') {
        Some(b) => (-1, b),
        None => (1, offset.trim_start_matches('+')),
    };
    let mut parts = body.split(':').map(|p| p.parse::<i32>().ok());
    let hours = parts.next()??;
    let minutes = parts.next().flatten().unwrap_or(0);
    Some((name, sign * (hours * 60 + minutes)))
}

#[cfg(test)]
mod tests;
