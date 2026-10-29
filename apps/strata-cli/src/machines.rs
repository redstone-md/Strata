//! `machines` and `usage` subcommands: one profile per installation found on each disk, and
//! when each disk was in use.

use strata_workbench::{EvidenceId, Machine, Period, UsageReport, Values, Workbench};

type Res = Result<(), Box<dyn std::error::Error>>;

fn disks(wb: &Workbench, disk: Option<u32>) -> Result<Vec<(EvidenceId, String)>, Box<dyn std::error::Error>> {
    let all = wb.evidence()?.into_iter().map(|e| (e.id, e.info.label)).filter(|(id, _)| disk.is_none_or(|d| id.get() == d)).collect::<Vec<_>>();
    if all.is_empty() {
        return Err(disk.map_or_else(|| "the case has no disks".to_string(), |d| format!("no disk {d}")).into());
    }
    Ok(all)
}

pub fn machines(wb: &Workbench, disk: Option<u32>, json: bool) -> Res {
    for (id, label) in disks(wb, disk)? {
        let found = wb.machines(id)?;
        if json {
            println!("{}", serde_json::json!({ "disk": id.get(), "label": label, "usage": found.usage, "machines": found.machines }));
            continue;
        }
        println!("Disk {id}  {label}");
        print_usage("  ", &found.usage);
        if found.machines.is_empty() {
            println!("  no installation found (run the Artifacts step first)");
        }
        for m in &found.machines {
            println!();
            print_machine(m);
        }
        println!();
    }
    Ok(())
}

pub fn usage(wb: &Workbench, disk: Option<u32>, json: bool) -> Res {
    for (id, label) in disks(wb, disk)? {
        let found = wb.machines(id)?;
        if json {
            let machines: Vec<_> = found.machines.iter().map(|m| serde_json::json!({ "machine": m.profile.label(), "usage": m.usage })).collect();
            println!("{}", serde_json::json!({ "disk": id.get(), "label": label, "usage": found.usage, "machines": machines }));
            continue;
        }
        println!("Disk {id}  {label}");
        print_usage("  ", &found.usage);
        for p in &found.usage.periods {
            println!("    {}", period(p));
        }
        for m in found.machines.iter().filter(|m| !m.usage.is_empty()) {
            println!("  {}:", m.profile.label());
            print_usage("    ", &m.usage);
        }
    }
    Ok(())
}

fn day(t: impl ToString) -> String {
    t.to_string().chars().take(10).collect()
}

fn period(p: &Period) -> String {
    let kinds: Vec<String> = p.kinds.iter().map(|k| format!("{} {}", k.kind.label(), k.events)).collect();
    format!("{} – {}  {} active days, {} events: {}", day(p.from.0), day(p.to.0), p.active_days, p.events, kinds.join(", "))
}

fn print_usage(indent: &str, u: &UsageReport) {
    let Some(range) = u.range_label() else {
        println!("{indent}in use: no dated user activity");
        return;
    };
    let hours = u.typical_hours.map(|(a, b)| format!(", mostly {a:02}:00–{b:02}:00")).unwrap_or_default();
    println!(
        "{indent}in use {range} ({}): {} active days in {} periods, {:.1} days a month{hours}",
        u.clock,
        u.active_days,
        u.periods.len(),
        u.days_per_month
    );
    if let Some(last) = &u.last_day {
        println!("{indent}last active day {}", day(last.0));
    }
    if !u.outliers.is_empty() || u.out_of_range > 0 {
        let strays: Vec<String> = u.outliers.iter().map(|o| format!("{} ({} events)", day(o.from.0), o.events)).collect();
        println!("{indent}left out: {} events with impossible dates; strays {}", u.out_of_range, if strays.is_empty() { "none".into() } else { strays.join(", ") });
    }
}

/// `value  [SYSTEM]`, with `(+N other values)` when files disagree.
fn sourced(values: &Values<String>) -> Option<String> {
    let p = values.primary()?;
    let others = values.len() - 1;
    let more = if others > 0 { format!(" (+{others} other)") } else { String::new() };
    Some(format!("{}{more}  [{}]", p.value, p.source().map_or("", |s| s.file_name())))
}

fn line(label: &str, value: Option<String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        println!("  {label:<14}{v}");
    }
}

fn print_machine(m: &Machine) {
    let p = &m.profile;
    println!("{}  {:?}{}", p.label(), p.kind, p.place().map(|s| format!(" {s}")).unwrap_or_default());
    line("computer", sourced(&p.computer_name));
    line("system", p.os.label());
    line("installed", p.os.install_date.value().map(|t| day(t.0)));
    line("system root", sourced(&p.os.system_root));
    line("owner", sourced(&p.owner).map(|o| p.organization.value().map_or(o.clone(), |org| format!("{o}, {org}"))));
    line("time zone", p.time_zone.label());
    line("last shutdown", p.last_shutdown().map(|t| t.to_string()));
    for u in p.people() {
        let mut parts = vec![u.name.clone()];
        parts.extend(u.full_name.clone());
        parts.extend(u.last_logon.map(|t| format!("last logon {t}")));
        parts.extend(u.logon_count.filter(|n| *n > 0).map(|n| format!("{n} logons")));
        parts.extend(u.last_activity.map(|t| format!("last activity {}", day(t))));
        line("user", Some(parts.join(", ")));
    }
    line("domain", sourced(&p.network.domain));
    for i in p.network.interfaces.iter() {
        let r = &i.value;
        let via = r.adapter.as_deref().map(|a| format!(" on {a}")).unwrap_or_default();
        let gw = if r.gateways.is_empty() { String::new() } else { format!(", gateway {}", r.gateways.join(" ")) };
        line("address", Some(format!("{}{via}{gw}{}", r.addresses.join(" "), if r.dhcp { " (DHCP)" } else { "" })));
    }
    for n in &p.network.profiles {
        let when = match (n.first_connected, n.last_connected) {
            (Some(a), Some(b)) => format!(" {} – {}", day(a), day(b)),
            (None, Some(b)) => format!(" last {}", day(b)),
            _ => String::new(),
        };
        line("network", Some(format!("{}{}{when}", n.name, n.kind.as_deref().map(|k| format!(" ({k})")).unwrap_or_default())));
    }
    for (label, v) in [("cpu", &p.hardware.cpu), ("video", &p.hardware.video), ("board", &p.hardware.system), ("disk drive", &p.hardware.disks)] {
        for item in v.iter() {
            line(label, Some(item.value.clone()));
        }
    }
    for d in &p.usb {
        let when = d.last_connected.map(|t| format!(", last {}{}", day(t), if d.approximate { " (approx.)" } else { "" })).unwrap_or_default();
        line("usb", Some(format!("{} [{}]{when}", d.name, d.kind)));
    }
    for s in &p.software {
        let mut parts = vec![format!("{} ({})", s.name, s.kind)];
        parts.extend(s.installed.map(|t| format!("installed {}", day(t))));
        parts.extend(s.last_used.map(|t| format!("last used {}", day(t))));
        parts.extend(s.data_dirs.iter().map(|d| format!("data {d}")));
        line("crypto", Some(parts.join(", ")));
    }
    if !p.linked_machines.is_empty() {
        line("other pcs", Some(p.linked_machines.iter().map(|m| m.value.clone()).collect::<Vec<_>>().join(", ")));
    }
    print_usage("  ", &m.usage);
}
