//! Event-id knowledge: which records become logons, account changes, boots/shutdowns,
//! installs; everything else is a generic system-log event.

use super::record::EventRecord;
use crate::results::{IdentityKind, Recorder};
use strata_timeline::EventKind;

const SECURITY: &str = "security-auditing";
const LOCAL_SESSIONS: &str = "terminalservices-localsessionmanager";
const REMOTE_CONNECTIONS: &str = "terminalservices-remoteconnectionmanager";
/// Built-in principals that are not people.
const SERVICE_ACCOUNTS: &[&str] = &["system", "local service", "network service", "anonymous logon", "dwm-1", "umfd-0", "umfd-1"];

/// Turn one record into timeline events (and identities for interactive users).
pub(super) fn emit(r: &EventRecord, rec: &mut Recorder) {
    let provider = r.provider.to_ascii_lowercase();
    let id = r.event_id.unwrap_or(0);
    let security = provider.contains(SECURITY) || r.channel.eq_ignore_ascii_case("security");
    let mapped = match (id, provider.as_str()) {
        (4624 | 4625 | 4634 | 4647 | 4648, _) if security => logon(r, id, rec),
        (4720 | 4726, _) if security => account(r, id, rec),
        (6005 | 6006 | 6008, "eventlog") | (1074, "user32") => power(r, id, rec),
        (7045, "service control manager") => service(r, rec),
        (1033 | 11707, "msiinstaller") => install(r, rec),
        (21..=25, p) if p.contains(LOCAL_SESSIONS) => session(r, id, rec),
        (1149, p) if p.contains(REMOTE_CONNECTIONS) => session(r, id, rec),
        _ => false,
    };
    if !mapped {
        let name = if r.provider.is_empty() { "unknown provider" } else { r.provider.as_str() };
        rec.dated(r.time, EventKind::SystemLog, format!("{name} event {id}"), detail(r, ""));
    }
}

fn detail(r: &EventRecord, lead: &str) -> String {
    let mut parts = Vec::new();
    if !lead.is_empty() {
        parts.push(lead.to_string());
    }
    parts.push(format!("record {}", r.record_id));
    if !r.channel.is_empty() {
        parts.push(format!("channel {}", r.channel));
    }
    if !r.computer.is_empty() {
        parts.push(format!("computer {}", r.computer));
    }
    let data = r.summary();
    if !data.is_empty() {
        parts.push(data);
    }
    parts.join("; ")
}

fn push(rec: &mut Recorder, r: &EventRecord, kind: EventKind, title: String, lead: &str, actor: Option<&str>) {
    if let Some(e) = rec.make(r.time, kind, title) {
        let e = e.with_detail(detail(r, lead));
        rec.push(match actor {
            Some(a) => e.with_actor(a),
            None => e,
        });
    }
}

fn is_person(user: &str) -> bool {
    !user.ends_with('$') && !SERVICE_ACCOUNTS.iter().any(|s| user.eq_ignore_ascii_case(s))
}

fn qualified(domain: Option<&str>, user: &str) -> String {
    match domain {
        Some(d) => format!("{d}\\{user}"),
        None => user.to_string(),
    }
}

fn logon_type(t: &str) -> &'static str {
    match t.trim() {
        "2" => "interactive",
        "3" => "network",
        "4" => "batch",
        "5" => "service",
        "7" => "unlock",
        "8" => "network cleartext",
        "9" => "new credentials",
        "10" => "remote interactive (RDP)",
        "11" => "cached interactive",
        _ => "other",
    }
}

fn logon(r: &EventRecord, id: u32, rec: &mut Recorder) -> bool {
    let Some(user) = r.get("TargetUserName") else { return false };
    let who = qualified(r.get("TargetDomainName"), user);
    let kind = r.get("LogonType").map(|t| format!("type {t}, {}", logon_type(t)));
    let what = match id {
        4624 => "Logon",
        4625 => "Failed logon",
        4634 => "Logoff",
        4647 => "User-initiated logoff",
        _ => "Logon with explicit credentials",
    };
    let mut title = format!("{what}: {who}");
    if let Some(k) = &kind {
        title.push_str(&format!(" ({k})"));
    }
    if id == 4648
        && let Some(by) = r.get("SubjectUserName")
    {
        title.push_str(&format!(" by {by}"));
    }
    let person = is_person(user);
    push(rec, r, EventKind::Login, title, what, person.then_some(user));
    if person && matches!(id, 4624 | 4648) {
        rec.identity(IdentityKind::Login, user, Some("Windows"), r.time);
    }
    true
}

fn account(r: &EventRecord, id: u32, rec: &mut Recorder) -> bool {
    let Some(user) = r.get("TargetUserName") else { return false };
    let what = if id == 4720 { "User account created" } else { "User account deleted" };
    let mut title = format!("{what}: {}", qualified(r.get("TargetDomainName"), user));
    if let Some(by) = r.get("SubjectUserName") {
        title.push_str(&format!(" by {by}"));
    }
    push(rec, r, EventKind::AccountSeen, title, what, None);
    rec.identity(IdentityKind::Login, user, Some("Windows"), r.time);
    true
}

fn power(r: &EventRecord, id: u32, rec: &mut Recorder) -> bool {
    let title = match id {
        6005 => "System start (event log service started)".to_string(),
        6006 => "System shutdown (event log service stopped)".to_string(),
        6008 => "Unexpected shutdown recorded".to_string(),
        _ => {
            let by = r.get("param7").or_else(|| r.unnamed().nth(6)).unwrap_or("unknown user");
            let process = r.get("param1").or_else(|| r.unnamed().next()).unwrap_or("unknown process");
            let action = r.get("param5").or_else(|| r.unnamed().nth(4)).unwrap_or("shutdown");
            format!("{action} initiated by {by} ({process})")
        }
    };
    push(rec, r, EventKind::SystemLog, title, "power", None);
    true
}

fn service(r: &EventRecord, rec: &mut Recorder) -> bool {
    let name = r.get("ServiceName").or_else(|| r.unnamed().next()).unwrap_or("unknown service");
    let image = r.get("ImagePath").or_else(|| r.unnamed().nth(1)).unwrap_or("");
    let by = r.get("AccountName").unwrap_or("");
    let title = if image.is_empty() { format!("Service installed: {name}") } else { format!("Service installed: {name} ({image})") };
    push(rec, r, EventKind::ProgramInstalled, title, &format!("service account {by}"), None);
    true
}

fn install(r: &EventRecord, rec: &mut Recorder) -> bool {
    let product = r.unnamed().next().unwrap_or("unknown product");
    let product = product.trim_start_matches("Product: ").split(" -- ").next().unwrap_or(product).to_string();
    push(rec, r, EventKind::ProgramInstalled, format!("Installed: {product}"), "Windows Installer", None);
    true
}

fn session(r: &EventRecord, id: u32, rec: &mut Recorder) -> bool {
    let user = r.get("User").or_else(|| r.get("Param1")).unwrap_or("unknown user");
    let from = r.get("Address").or_else(|| r.get("Param3")).filter(|a| *a != "LOCAL");
    let what = match id {
        21 => "Session logon",
        22 => "Session shell start",
        23 => "Session logoff",
        24 => "Session disconnected",
        25 => "Session reconnected",
        _ => "Remote Desktop authentication succeeded",
    };
    let mut title = format!("{what}: {user}");
    if let Some(addr) = from {
        title.push_str(&format!(" from {addr}"));
    }
    let short = user.rsplit('\\').next().unwrap_or(user);
    push(rec, r, EventKind::Login, title, "Terminal Services", is_person(short).then_some(short));
    true
}
