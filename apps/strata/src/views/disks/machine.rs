//! One installation as a compact card: what the computer was, who used it, how it was
//! connected, what crypto software it ran and when it was in use. Each line carries a quiet
//! hint of the file it was read from.

use super::usage::{ActivityStrip, day, rhythm};
use crate::theme::tokens;
use gpui::{IntoElement, ParentElement, SharedString, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{InstallKind, Machine, MachineProfile, Provenance, Values, first_source};

/// Width of the label column.
const LABEL: f32 = 96.;
/// Entries shown per list line (users, networks, USB, software); the rest are counted.
const MAX_ITEMS: usize = 3;

/// One card line: label, value, source hint.
struct Line {
    label: &'static str,
    value: String,
    source: Option<String>,
}

fn hint(p: Option<&Provenance>) -> Option<String> {
    p.map(|s| s.file_name().to_string())
}

fn sourced(label: &'static str, v: &Values<String>) -> Option<Line> {
    let p = v.primary()?;
    let others = v.len() - 1;
    let value = if others > 0 { format!("{} (+{others} other)", p.value) } else { p.value.clone() };
    Some(Line { label, value, source: hint(p.source()) })
}

/// `a; b; c +2 more`.
fn joined(items: Vec<String>) -> Option<String> {
    let more = items.len().saturating_sub(MAX_ITEMS);
    let mut text = items.into_iter().take(MAX_ITEMS).collect::<Vec<_>>().join("; ");
    if more > 0 {
        text.push_str(&format!("  +{more} more"));
    }
    (!text.is_empty()).then_some(text)
}

fn kind_note(p: &MachineProfile) -> String {
    let what = match p.kind {
        InstallKind::System => p.family().to_string(),
        InstallKind::Previous => format!("previous {}", p.family()),
        InstallKind::Copy => format!("copied {}", p.family()),
        InstallKind::Container => "container".into(),
        InstallKind::HomeVolume => "home folders".into(),
    };
    match p.place() {
        Some(place) => format!("{what} {place}"),
        None => what,
    }
}

/// `Windows 7 Home Premium SP1 · 6.1.7601` (the card is narrow; the CLI and MCP say it in full).
fn os_short(p: &MachineProfile) -> Option<String> {
    let os = &p.os;
    let mut text = os.product.value()?.clone();
    if let Some(sp) = os.service_pack.value() {
        let n = sp.trim_start_matches("Service Pack ").trim();
        text.push_str(&if n.len() <= 2 { format!(" SP{n}") } else { format!(", {sp}") });
    }
    let number = match (os.version.value(), os.build.value()) {
        (Some(v), Some(b)) => Some(format!("{v}.{b}")),
        (v, b) => v.or(b).cloned(),
    };
    if let Some(n) = number {
        text.push_str(&format!(" · {n}"));
    }
    Some(text)
}

fn lines(p: &MachineProfile) -> Vec<Line> {
    let mut out = Vec::new();
    if let Some(os) = os_short(p) {
        out.push(Line { label: "System", value: os, source: hint(first_source(&p.os.product)) });
    }
    if let Some(d) = p.os.install_date.primary() {
        out.push(Line { label: "Installed", value: day(d.value.0), source: hint(d.source()) });
    }
    out.extend(sourced("Owner", &p.owner).map(|mut l| {
        if let Some(org) = p.organization.value() {
            l.value = format!("{}, {org}", l.value);
        }
        l
    }));
    let users: Vec<String> = p
        .people()
        .map(|u| {
            let seen = u.last_seen().map(|t| format!(" · last {}", day(t))).unwrap_or_default();
            let count = u.logon_count.filter(|n| *n > 0).map(|n| format!(" · {n} logons")).unwrap_or_default();
            format!("{}{seen}{count}", u.name)
        })
        .collect();
    if let Some(value) = joined(users) {
        out.push(Line { label: "Users", value, source: hint(p.users.first().and_then(|u| u.sources.first())) });
    }
    if let Some(value) = p.time_zone.label() {
        out.push(Line { label: "Time zone", value, source: hint(first_source(&p.time_zone.name).or(first_source(&p.time_zone.bias_minutes))) });
    }
    if let Some(t) = p.last_shutdown() {
        out.push(Line { label: "Shutdown", value: t.to_string(), source: hint(first_source(&p.last_shutdown)) });
    }
    let mut net: Vec<String> = p.network.domain.iter().map(|d| format!("domain {}", d.value)).collect();
    net.extend(p.network.interfaces.iter().map(|i| {
        let r = &i.value;
        format!("{}{}", r.addresses.join(" "), if r.dhcp { " (DHCP)" } else { "" })
    }));
    if let Some(value) = joined(net) {
        out.push(Line { label: "Network", value, source: hint(p.network.interfaces.primary().and_then(|i| i.source())) });
    }
    let wifi: Vec<String> = p
        .network
        .profiles
        .iter()
        .map(|n| {
            let when = match (n.first_connected, n.last_connected) {
                (Some(a), Some(b)) => format!(" {} – {}", day(a), day(b)),
                (None, Some(b)) => format!(" last {}", day(b)),
                _ => String::new(),
            };
            format!("{}{when}", n.name)
        })
        .collect();
    if let Some(value) = joined(wifi) {
        out.push(Line { label: "Networks", value, source: hint(p.network.profiles.first().and_then(|n| n.sources.first())) });
    }
    let hw = &p.hardware;
    let hardware: Vec<String> = [&hw.cpu, &hw.video, &hw.system].iter().filter_map(|v| v.value().cloned()).collect();
    if let Some(value) = joined(hardware) {
        out.push(Line { label: "Hardware", value, source: hint(first_source(&hw.cpu).or(first_source(&hw.video))) });
    }
    let usb: Vec<String> = p
        .usb
        .iter()
        .map(|d| {
            let when = d.last_connected.map(|t| format!(" · {}{}", if d.approximate { "≈" } else { "" }, day(t))).unwrap_or_default();
            let kind = if d.kind == "storage" { String::new() } else { format!(" ({})", d.kind) };
            format!("{}{kind}{when}", d.name)
        })
        .collect();
    if let Some(value) = joined(usb) {
        out.push(Line { label: "USB", value, source: hint(p.usb.first().and_then(|d| d.sources.first())) });
    }
    let software: Vec<String> = p
        .software
        .iter()
        .map(|s| {
            let mut text = s.name.clone();
            if let Some(t) = s.installed {
                text.push_str(&format!(" · installed {}", day(t)));
            }
            if let Some(t) = s.last_used {
                text.push_str(&format!(" · used {}", day(t)));
            }
            text
        })
        .collect();
    if let Some(value) = joined(software) {
        out.push(Line { label: "Crypto", value, source: hint(p.software.first().and_then(|s| s.sources.first())) });
    }
    out
}

fn row(line: Line) -> impl IntoElement {
    let t = tokens();
    h_flex()
        .min_h(px(24.))
        .gap(px(12.))
        .border_b_1()
        .border_color(t.row_rule)
        .text_size(t.size_body)
        .child(div().w(px(LABEL)).flex_shrink_0().text_color(t.text_secondary).child(line.label))
        .child(div().flex_1().min_w_0().text_color(t.text).truncate().child(line.value))
        .children(line.source.map(|s| div().flex_shrink_0().max_w(px(140.)).truncate().text_size(t.size_small).text_color(t.text_secondary).child(s)))
}

/// The card of one installation.
pub fn card(m: &Machine) -> impl IntoElement {
    let t = tokens();
    let p = &m.profile;
    let title = h_flex()
        .gap_3()
        .items_baseline()
        .min_w_0()
        .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).truncate().child(SharedString::from(p.label())))
        .child(div().text_size(t.size_body).text_color(t.text_secondary).truncate().child(kind_note(p)));
    let usage = m.usage.range_label().map(|range| {
        let last = m.usage.last_day.map(|d| format!(" · last active {}", day(d.0))).unwrap_or_default();
        v_flex()
            .gap(px(4.))
            .pt(px(6.))
            .child(h_flex().gap(px(12.)).text_size(t.size_body).child(div().w(px(LABEL)).flex_shrink_0().text_color(t.text_secondary).child("In use")).child(div().text_color(t.text).child(format!("{range}{last}"))))
            .child(div().pl(px(LABEL + 12.)).child(ActivityStrip::new(&m.usage).height(px(16.))))
            .child(div().pl(px(LABEL + 12.)).text_size(t.size_small).text_color(t.text_secondary).child(rhythm(&m.usage)))
    });
    v_flex()
        .w(px(470.))
        .min_w(px(360.))
        .flex_shrink(1.)
        .gap(px(8.))
        .child(title)
        .child(v_flex().border_t_1().border_color(t.row_rule).children(lines(p).into_iter().map(row)))
        .children(usage)
}
