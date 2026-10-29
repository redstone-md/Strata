//! Background jobs as plain rows: what, on which disk, and its state in words.

use crate::format;
use crate::session::{Session, Snapshot};
use crate::theme::tokens;
use crate::widgets::{Badge, Section, TextButton, quiet};
use gpui::{AnyElement, Entity, IntoElement, ParentElement, Styled, div, px};
use strata_workbench::{JobKind, JobState, JobView};
use gpui_component::{h_flex, v_flex};

const MAX_ROWS: usize = 10;

fn title(job: &JobView, snapshot: &Snapshot) -> String {
    match job.kind {
        JobKind::CheckBalances => format::job_name(job.kind).to_string(),
        kind => format!("{} {}", format::job_name(kind), snapshot.disk_label(job.evidence)),
    }
}

/// State column: words, a summary or reason after it, an inverted badge for failures.
fn state(job: &JobView) -> AnyElement {
    let t = tokens();
    let line = h_flex().gap(px(8.)).min_w_0().text_size(t.size_body);
    match &job.state {
        JobState::Failed(reason) => {
            line.child(Badge::inverted("failed")).child(div().text_color(t.text).truncate().child(reason.clone())).into_any_element()
        }
        JobState::Done(summary) => line
            .child(div().text_color(t.text_secondary).truncate().child(format!("done — {summary}")))
            .into_any_element(),
        JobState::Running => line.child(div().text_color(t.emphasis).child(format::job_state(job))).into_any_element(),
        _ => line.child(div().text_color(t.text_secondary).child(format::job_state(job))).into_any_element(),
    }
}

pub fn section(snapshot: &Snapshot, session: &Entity<Session>) -> impl IntoElement {
    let t = tokens();
    let rows: Vec<_> = snapshot
        .jobs
        .iter()
        .rev()
        .take(MAX_ROWS)
        .map(|job| {
            let active = matches!(job.state, JobState::Queued | JobState::Running);
            let cancel = active.then(|| {
                let (session, id) = (session.clone(), job.id);
                TextButton::new(("cancel-job", id.0 as usize), "Cancel")
                    .on_click(move |_, _, cx| session.update(cx, |s, cx| s.cancel(id, cx)))
            });
            h_flex()
                .min_h(t.row_height)
                .py(px(4.))
                .gap(px(16.))
                .border_b_1()
                .border_color(t.row_rule)
                .child(div().w(px(240.)).flex_shrink_0().text_size(t.size_body).text_color(t.text).truncate().child(title(job, snapshot)))
                .child(div().flex_1().min_w_0().child(state(job)))
                .children(cancel)
        })
        .collect();
    let empty = rows.is_empty().then(|| quiet().child("No jobs yet. Analyse a disk to index its files and scan it."));
    Section::new("Jobs")
        .flex_1()
        .child(v_flex().border_t_1().border_color(t.row_rule).children(rows))
        .children(empty)
}
