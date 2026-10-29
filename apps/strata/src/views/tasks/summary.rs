//! The live process row: CPU, memory, GPU, GPU memory, disk read and write — each a number
//! over a five-minute sparkline — and the machine around it in one quiet line.

use crate::format;
use crate::theme::tokens;
use crate::widgets::{Sparkline, mono, quiet};
use gpui::{IntoElement, ParentElement, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{MonitorView, ResourceSample};

/// Samples the sparklines span: five minutes at one per second.
pub const SLOTS: usize = 300;

struct Metric {
    label: &'static str,
    value: String,
    note: String,
    series: Vec<f32>,
    max: Option<f32>,
}

fn metric(label: &'static str, value: String, note: impl Into<String>, series: Vec<f32>, max: Option<f32>) -> Metric {
    Metric { label, value, note: note.into(), series, max }
}

fn series(samples: &[ResourceSample], f: impl Fn(&ResourceSample) -> f32) -> Vec<f32> {
    samples[samples.len().saturating_sub(SLOTS)..].iter().map(f).collect()
}

fn metrics(m: &MonitorView) -> Vec<Metric> {
    let s = &m.process;
    let Some(now) = m.latest() else {
        return ["CPU", "Memory", "GPU", "GPU memory", "Disk read", "Disk write"]
            .into_iter()
            .map(|l| metric(l, "—".into(), "waiting for the first sample", Vec::new(), None))
            .collect();
    };
    let gpu_missing = "not available";
    vec![
        metric("CPU", format!("{:.0}%", now.cpu), format!("of {} cores", m.cores), series(s, |x| x.cpu), Some(100.0)),
        metric(
            "Memory",
            format::bytes(now.working_set),
            format!("private {}", format::bytes(now.private_bytes)),
            series(s, |x| x.working_set as f32),
            None,
        ),
        match now.gpu {
            Some(g) => metric("GPU", format!("{g:.0}%"), "renderer, busiest engine", series(s, |x| x.gpu.unwrap_or(0.0)), Some(100.0)),
            None => metric("GPU", "—".into(), gpu_missing, Vec::new(), None),
        },
        match now.gpu_memory {
            Some(b) => metric("GPU memory", format::bytes(b), "dedicated", series(s, |x| x.gpu_memory.unwrap_or(0) as f32), None),
            None => metric("GPU memory", "—".into(), gpu_missing, Vec::new(), None),
        },
        metric(
            "Disk read",
            format!("{}/s", format::bytes(now.read_per_sec as u64)),
            "evidence, case and caches",
            series(s, |x| x.read_per_sec as f32),
            None,
        ),
        metric(
            "Disk write",
            format!("{}/s", format::bytes(now.write_per_sec as u64)),
            "case database and caches",
            series(s, |x| x.write_per_sec as f32),
            None,
        ),
    ]
}

fn cell(m: Metric) -> impl IntoElement {
    let t = tokens();
    let line = Sparkline::new(m.series, SLOTS);
    let line = match m.max {
        Some(max) => line.max(max),
        None => line,
    };
    v_flex()
        .flex_1()
        .min_w_0()
        .gap(px(4.))
        .child(div().text_size(t.size_small).text_color(t.text_secondary).child(m.label))
        .child(mono().text_size(t.size_heading).text_color(t.emphasis).truncate().child(m.value))
        .child(div().text_size(t.size_small).text_color(t.text_secondary).truncate().child(m.note))
        .child(div().pt(px(4.)).child(line))
}

pub fn row(m: &MonitorView) -> impl IntoElement {
    v_flex()
        .gap(px(12.))
        .child(h_flex().items_start().gap(px(32.)).children(metrics(m).into_iter().map(cell)))
        .child(system_line(m))
}

fn system_line(m: &MonitorView) -> impl IntoElement {
    let mut parts = Vec::new();
    if let Some(s) = m.system {
        parts.push(format!("System CPU {:.0}%", s.cpu));
        parts.push(format!("free memory {} of {}", format::bytes(s.free_ram), format::bytes(s.total_ram)));
    }
    if let Some(n) = m.latest().and_then(|p| p.threads) {
        parts.push(format::count(u64::from(n), "thread", "threads"));
    }
    parts.push("last 5 minutes".into());
    quiet().text_size(tokens().size_small).child(parts.join("  ·  "))
}
