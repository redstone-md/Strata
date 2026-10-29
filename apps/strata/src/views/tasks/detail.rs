//! The selected job in depth: its checkpoint and what it resumes from, its own CPU over the
//! last five minutes, and its recent log.

use super::summary::SLOTS;
use crate::format;
use crate::theme::tokens;
use crate::widgets::{Section, Sparkline, mono, quiet};
use gpui::{AnyElement, IntoElement, ParentElement, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{JobState, JobView, LogLine, MonitorView, ProgressUnit};

/// Log lines shown.
const LOG_LINES: usize = 14;

fn fact(label: &'static str, value: String) -> impl IntoElement {
    let t = tokens();
    h_flex()
        .min_h(px(24.))
        .gap(px(12.))
        .text_size(t.size_body)
        .border_b_1()
        .border_color(t.row_rule)
        .child(div().w(px(120.)).flex_shrink_0().text_color(t.text_secondary).child(label))
        .child(div().flex_1().min_w_0().text_color(t.text).truncate().child(value))
}

fn amount(job: &JobView, n: u64) -> String {
    match job.unit {
        ProgressUnit::Bytes => format::bytes(n),
        ProgressUnit::Items => format!("{n} {}", format::items(job.kind)),
    }
}

fn facts(job: &JobView) -> impl IntoElement {
    let p = &job.progress;
    let (saved, resume) = match &job.checkpoint {
        Some(c) => (format!("saved {}", format::ago(c.saved_at)), c.note.clone()),
        None => ("none yet".to_string(), "the beginning".to_string()),
    };
    let progress = if p.total > 0 { format!("{} of {}", amount(job, p.scanned), amount(job, p.total)) } else { "—".into() };
    let resume_label = match job.state {
        JobState::Running => Some("Would resume from"),
        JobState::Queued | JobState::Done(_) => None,
        _ => Some("Resumes from"),
    };
    v_flex()
        .w(px(380.))
        .flex_shrink_0()
        .children(resume_label.map(|_| fact("Checkpoint", saved)))
        .children(resume_label.map(|label| fact(label, resume)))
        .children(job.finished_at.filter(|_| matches!(job.state, JobState::Done(_))).map(|f| fact("Finished", format::ago(f))))
        .child(fact("Progress", progress))
        .child(fact("Evidence read", format::bytes(p.read_bytes)))
        .child(fact("Findings", p.hits.to_string()))
        .child(fact("Queued", format::ago(job.created_at)))
        .child(fact("Started", job.started_at.map_or("not yet".into(), format::ago)))
}

fn cpu(job: &JobView, monitor: &MonitorView) -> impl IntoElement {
    let t = tokens();
    let samples = monitor.jobs.get(&job.id).cloned().unwrap_or_default();
    let values: Vec<f32> = samples.iter().map(|s| s.cpu).collect();
    let peak = values.iter().copied().fold(0.0, f32::max);
    let source = if monitor.per_thread_cpu { "its own threads" } else { "its share of the process" };
    let caption = match values.last() {
        Some(now) => format!("now {now:.0}%, peak {peak:.0}% of all cores, from {source}"),
        None => "Measured while the job runs.".to_string(),
    };
    v_flex()
        .flex_1()
        .min_w_0()
        .gap(px(8.))
        .child(div().text_size(t.size_small).text_color(t.text_secondary).child("CPU of this job, last 5 minutes"))
        .child(Sparkline::new(values, SLOTS).max(100.).height(px(64.)))
        .child(div().text_size(t.size_small).text_color(t.text_secondary).child(caption))
}

fn log(lines: &[LogLine]) -> AnyElement {
    let t = tokens();
    let shown = &lines[lines.len().saturating_sub(LOG_LINES)..];
    let body: AnyElement = if shown.is_empty() {
        quiet().child("No log lines yet.").into_any_element()
    } else {
        v_flex()
            .gap(px(2.))
            .children(shown.iter().map(|l| {
                h_flex()
                    .gap(px(12.))
                    .text_size(t.size_small)
                    .child(div().w(px(84.)).flex_shrink_0().text_color(t.text_secondary).child(format::ago(l.at)))
                    .child(mono().flex_1().min_w_0().text_color(t.text).truncate().child(l.text.clone()))
            }))
            .into_any_element()
    };
    v_flex()
        .w(px(460.))
        .flex_shrink_0()
        .gap(px(8.))
        .child(div().text_size(t.size_small).text_color(t.text_secondary).child("Log"))
        .child(body)
        .into_any_element()
}

pub fn section(job: &JobView, title: String, monitor: &MonitorView, lines: &[LogLine]) -> AnyElement {
    Section::new(title)
        .note(format::job_state_long(job))
        .child(h_flex().items_start().gap(px(48.)).child(facts(job)).child(cpu(job, monitor)).child(log(lines)))
        .into_any_element()
}
