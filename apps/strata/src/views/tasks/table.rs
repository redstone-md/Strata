//! Every job as one flat row: what, its state in words, progress, the item it works on, its
//! throughput, time left, its CPU and evidence reads, and Pause / Resume / Cancel.

use super::TasksView;
use crate::format;
use crate::session::{Session, Snapshot};
use crate::theme::tokens;
use crate::widgets::{TextButton, mono, quiet};
use gpui::{
    AnyElement, Context, Div, Entity, InteractiveElement as _, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement as _, Styled, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use std::time::Duration;
use strata_workbench::{JobId, JobState, JobView, MonitorView};

/// Rows shown: active jobs first, then the most recent finished ones.
const MAX_ROWS: usize = 40;
/// Characters of the current item before its middle is cut.
const CURRENT_CHARS: usize = 34;

/// `(header, width)`; `None` width takes the remaining space.
const COLUMNS: [(&str, Option<f32>, bool); 10] = [
    ("Job", Some(184.), false),
    ("State", Some(172.), false),
    ("Progress", Some(60.), true),
    ("Current item", None, false),
    ("Throughput", Some(92.), true),
    ("Time left", Some(64.), true),
    ("CPU", Some(44.), true),
    ("Read", Some(64.), true),
    ("Elapsed", Some(64.), true),
    ("", Some(124.), true),
];

fn column(i: usize) -> Div {
    let (_, width, right) = COLUMNS[i];
    let c = match width {
        Some(w) => div().w(px(w)).flex_shrink_0(),
        None => div().flex_1().min_w(px(120.)),
    };
    let c = c.min_w_0().truncate();
    if right { c.text_right() } else { c }
}

/// Jobs in display order.
pub fn ordered(jobs: &[JobView]) -> Vec<&JobView> {
    let rank = |j: &JobView| match j.state {
        JobState::Running => 0,
        JobState::Queued => 1,
        JobState::Interrupted => 2,
        _ => 3,
    };
    let mut out: Vec<&JobView> = jobs.iter().collect();
    out.sort_by(|a, b| rank(a).cmp(&rank(b)).then(b.id.cmp(&a.id)));
    out.truncate(MAX_ROWS);
    out
}

fn elapsed(job: &JobView) -> Option<Duration> {
    match (&job.state, job.started_at, job.finished_at) {
        (JobState::Running, _, _) => Some(Duration::from_secs_f64(job.progress.elapsed_secs)),
        (_, Some(s), Some(f)) => Some(Duration::from_secs((f - s).max(0) as u64)),
        _ => None,
    }
}

fn header() -> impl IntoElement {
    let t = tokens();
    h_flex()
        .h(t.row_height)
        .gap(px(16.))
        .px(px(8.))
        .text_size(t.size_small)
        .text_color(t.text_secondary)
        .border_b_1()
        .border_color(t.row_rule)
        .children((0..COLUMNS.len()).map(|i| column(i).child(COLUMNS[i].0)))
}

/// Pause / Resume / Cancel: on the running job and on the selected row, so a list of queued
/// jobs does not turn into a column of buttons.
fn actions(job: &JobView, selected: bool, session: &Entity<Session>) -> AnyElement {
    let mine = job.foreign.is_none() && (selected || job.state == JobState::Running);
    let id = job.id;
    let mut row = h_flex().gap(px(6.)).justify_end();
    if mine && job.state == JobState::Running {
        let s = session.clone();
        row = row.child(if job.is_paused() {
            TextButton::new(("resume-job", id.0 as usize), "Resume").on_click(move |_, _, cx| s.update(cx, |s, cx| s.resume(id, cx)))
        } else {
            TextButton::new(("pause-job", id.0 as usize), "Pause").on_click(move |_, _, cx| s.update(cx, |s, cx| s.pause(id, cx)))
        });
    }
    if mine && job.state.is_active() {
        let s = session.clone();
        row = row.child(
            TextButton::new(("cancel-task", id.0 as usize), "Cancel").on_click(move |_, _, cx| s.update(cx, |s, cx| s.cancel(id, cx))),
        );
    }
    row.into_any_element()
}

fn job_row(job: &JobView, title: String, monitor: &MonitorView, selected: bool, session: &Entity<Session>, cx: &mut Context<TasksView>) -> AnyElement {
    let t = tokens();
    let running = job.state == JobState::Running;
    let live = monitor.job_latest(job.id).filter(|_| running);
    let dash = || "—".to_string();
    let state_color = match job.state {
        JobState::Running if !job.is_paused() => t.emphasis,
        JobState::Failed(_) | JobState::Interrupted => t.text,
        _ => t.text_secondary,
    };
    let progress = if matches!(job.state, JobState::Queued) { dash() } else { format::percent(job.fraction()) };
    let id = job.id;
    h_flex()
        .id(SharedString::from(format!("task-{}", id.0)))
        .min_h(t.row_height)
        .py(px(1.))
        .gap(px(16.))
        .px(px(8.))
        .text_size(t.size_body)
        .text_color(t.text)
        .border_b_1()
        .border_color(t.row_rule)
        .cursor_pointer()
        .when(selected, |el| el.bg(t.selection))
        .when(!selected, |el| el.hover(|s| s.bg(t.hover)))
        .on_click(cx.listener(move |this, _, _, cx| this.select(id, cx)))
        .child(column(0).child(title))
        .child(column(1).text_color(state_color).child(format::job_state_long(job)))
        .child(column(2).child(progress))
        .child(column(3).child(mono().text_size(t.size_small).text_color(t.text_secondary).truncate().child(format::middle(&job.current, CURRENT_CHARS))))
        .child(column(4).child(live.map_or_else(dash, |s| format::rate(job, s.units_per_sec))))
        .child(column(5).child(job.eta().map_or_else(dash, format::duration)))
        .child(column(6).child(live.map_or_else(dash, |s| format!("{:.0}%", s.cpu))))
        .child(column(7).child(if job.progress.read_bytes > 0 { format::bytes(job.progress.read_bytes) } else { dash() }))
        .child(column(8).child(elapsed(job).map_or_else(dash, format::duration)))
        .child(column(9).child(actions(job, selected, session)))
        .into_any_element()
}

pub fn table(snapshot: &Snapshot, monitor: &MonitorView, selected: Option<JobId>, session: &Entity<Session>, cx: &mut Context<TasksView>) -> AnyElement {
    let rows: Vec<AnyElement> = ordered(&snapshot.jobs)
        .into_iter()
        .map(|j| job_row(j, snapshot.job_title(j), monitor, Some(j.id) == selected, session, cx))
        .collect();
    if rows.is_empty() {
        return quiet().child("Nothing has run in this case yet. Analyse a disk to start the pipeline.").into_any_element();
    }
    v_flex().child(header()).children(rows).into_any_element()
}
