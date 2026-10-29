//! The computers each disk served: one profile per operating-system installation (computer
//! name, Windows or Linux version, owner, users, time zone, network, hardware, USB devices,
//! crypto software) with the file each value came from, and when each disk and machine was in
//! use (first and last day, active periods, typical hours).

use crate::StrataServer;
use crate::format::{Reply, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{EvidenceId, Machine, MachineProfile, Period, Timestamp, UsageReport, Values, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MachinesParams {
    /// Only this disk id.
    pub disk: Option<u32>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UsageParams {
    /// Only this disk id.
    pub disk: Option<u32>,
    /// Also list every month of the in-use range with its active days.
    pub months: bool,
}

/// A value and the file it was read from; `others` when files disagree.
#[derive(Serialize)]
struct Field {
    value: String,
    source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    others: Vec<String>,
}

fn field(values: &Values<String>) -> Option<Field> {
    let p = values.primary()?;
    Some(Field {
        value: p.value.clone(),
        source: p.source().map(|s| s.path.clone()).unwrap_or_default(),
        others: values.others().map(|o| o.value.clone()).collect(),
    })
}

fn to_json<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

fn opt_time(t: Option<Timestamp>) -> Option<String> {
    t.map(time)
}

#[derive(Serialize)]
struct User {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_logon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logon_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activity: Option<String>,
}

#[derive(Serialize)]
struct Profile {
    label: String,
    /// System, Previous (Windows.old), Copy, Container, HomeVolume.
    kind: String,
    family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
    /// Folder above the system folders ("" at the volume root).
    root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    computer_name: Option<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    install_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_root: Option<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_shutdown: Option<String>,
    users: Vec<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<Field>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    networks: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hardware: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    usb_devices: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    crypto_software: Vec<serde_json::Value>,
    /// Other computers named in LNK files (network shares, copied links).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    other_computers: Vec<String>,
}

impl Profile {
    fn of(p: &MachineProfile) -> Self {
        let hw = &p.hardware;
        Self {
            label: p.label(),
            kind: format!("{:?}", p.kind),
            family: p.family().to_string(),
            volume: p.key.volume,
            root: p.key.root.clone(),
            computer_name: field(&p.computer_name),
            os: p.os.label(),
            install_date: p.os.install_date.value().map(|t| time(t.0)),
            system_root: field(&p.os.system_root),
            owner: field(&p.owner),
            organization: field(&p.organization),
            time_zone: p.time_zone.label(),
            last_shutdown: opt_time(p.last_shutdown()),
            users: p
                .people()
                .map(|u| User {
                    name: u.name.clone(),
                    full_name: u.full_name.clone(),
                    id: u.id.clone(),
                    home: u.home.clone(),
                    last_logon: opt_time(u.last_logon),
                    logon_count: u.logon_count,
                    last_activity: opt_time(u.last_activity),
                })
                .collect(),
            domain: field(&p.network.domain),
            interfaces: p.network.interfaces.iter().map(|i| to_json(&i.value)).collect(),
            networks: p.network.profiles.iter().map(to_json).collect(),
            hardware: [&hw.cpu, &hw.video, &hw.system, &hw.disks].iter().flat_map(|v| v.iter().map(|i| i.value.clone())).collect(),
            usb_devices: p.usb.iter().map(to_json).collect(),
            crypto_software: p.software.iter().map(to_json).collect(),
            other_computers: p.linked_machines.iter().map(|m| m.value.clone()).collect(),
        }
    }
}

#[derive(Serialize)]
struct PeriodOut {
    from: String,
    to: String,
    active_days: u32,
    events: u64,
    /// Events per kind of activity (logons, programs, web, documents, start-up/shutdown...).
    activity: Vec<(String, u64)>,
}

impl PeriodOut {
    fn of(p: &Period) -> Self {
        let day = |t: Timestamp| time(t).chars().take(10).collect();
        Self { from: day(p.from.0), to: day(p.to.0), active_days: p.active_days, events: p.events, activity: p.kinds.iter().map(|k| (k.kind.label().to_string(), k.events)).collect() }
    }
}

#[derive(Serialize)]
struct Usage {
    #[serde(skip_serializing_if = "Option::is_none")]
    first_day: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active_day: Option<String>,
    /// Clock of days and hours: the machine's UTC offset when known.
    clock: String,
    active_days: u32,
    days_per_month: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    typical_hours: Option<String>,
    /// Events per weekday, Monday first.
    weekdays: [u64; 7],
    periods: Vec<PeriodOut>,
    /// Small clusters far from the rest, left out of the range (reset clocks, stray files).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    outliers: Vec<(String, u64)>,
    /// Events with impossible dates (before 1995, after the image or today).
    out_of_range: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    months: Option<Vec<(String, u32)>>,
}

impl Usage {
    fn of(u: &UsageReport, months: bool) -> Self {
        let day = |t: Timestamp| time(t).chars().take(10).collect::<String>();
        Self {
            first_day: u.first_day.map(|w| day(w.0)),
            last_active_day: u.last_day.map(|w| day(w.0)),
            clock: u.clock.clone(),
            active_days: u.active_days,
            days_per_month: (u.days_per_month * 10.0).round() / 10.0,
            typical_hours: u.typical_hours.map(|(a, b)| format!("{a:02}:00-{b:02}:00")),
            weekdays: u.weekdays,
            periods: u.periods.iter().map(PeriodOut::of).collect(),
            outliers: u.outliers.iter().map(|o| (day(o.from.0), o.events)).collect(),
            out_of_range: u.out_of_range,
            months: months.then(|| u.months.iter().map(|m| (format!("{:04}-{:02}", m.year, m.month), m.active_days)).collect()),
        }
    }
}

#[derive(Serialize)]
struct MachineOut {
    profile: Profile,
    usage: Usage,
}

#[derive(Serialize)]
struct DiskOut<T> {
    disk: u32,
    label: String,
    usage: Usage,
    machines: Vec<T>,
}

#[derive(Serialize)]
struct MachineUsage {
    machine: String,
    usage: Usage,
}

fn disks(wb: &Workbench, disk: Option<u32>) -> Reply<Vec<(EvidenceId, String)>> {
    let all: Vec<_> = wb.evidence().map_err(fail)?.into_iter().map(|e| (e.id, e.info.label)).filter(|(id, _)| disk.is_none_or(|d| id.get() == d)).collect();
    match disk {
        Some(d) if all.is_empty() => Err(format!("no disk {d}; case_overview lists the disks")),
        _ => Ok(all),
    }
}

fn machines(wb: &Workbench, p: MachinesParams) -> Reply<Vec<DiskOut<MachineOut>>> {
    disks(wb, p.disk)?
        .into_iter()
        .map(|(id, label)| {
            let found = wb.machines(id).map_err(fail)?;
            let machines = found.machines.iter().map(|m: &Machine| MachineOut { profile: Profile::of(&m.profile), usage: Usage::of(&m.usage, false) }).collect();
            Ok(DiskOut { disk: id.get(), label, usage: Usage::of(&found.usage, false), machines })
        })
        .collect()
}

fn usage(wb: &Workbench, p: UsageParams) -> Reply<Vec<DiskOut<MachineUsage>>> {
    disks(wb, p.disk)?
        .into_iter()
        .map(|(id, label)| {
            let found = wb.machines(id).map_err(fail)?;
            let machines = found.machines.iter().map(|m| MachineUsage { machine: m.profile.label(), usage: Usage::of(&m.usage, p.months) }).collect();
            Ok(DiskOut { disk: id.get(), label, usage: Usage::of(&found.usage, p.months), machines })
        })
        .collect()
}

#[tool_router(router = machine_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "The computers found on each disk: one profile per operating-system installation (dual boot, Windows.old, \
        copied systems, containers) with computer name, Windows/Linux version, install date, owner, users with last logon, time \
        zone, last shutdown, network addresses and Wi-Fi networks, hardware, USB devices (hardware wallets first), crypto \
        software with install and use dates, and the file each value came from. Each machine also has its usage periods."
    )]
    pub async fn machines(&self, Parameters(p): Parameters<MachinesParams>) -> Reply<String> {
        self.query(move |wb| machines(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "When each disk and each machine on it was in use, from user activity only (logons, program runs, \
        browsing, documents, start-up/shutdown, USB, wallet traces; not file times): first and last active day, periods \
        of active use split by month-long gaps with counts per kind of activity, typical hours, weekdays, and dates left \
        out as impossible or stray. Days and hours are in the machine's local time when its time zone is known."
    )]
    pub async fn usage_periods(&self, Parameters(p): Parameters<UsageParams>) -> Reply<String> {
        self.query(move |wb| usage(wb, p)).await
    }
}
