//! Searches running right now, shown above the results: which disk is being read, how far it
//! got and how long is left, with a way to stop it. Without this the screen sits on "No
//! matches yet" and the work is only visible on Tasks.

use crate::format;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{TextButton, loading_line};
use gpui::{Entity, IntoElement, ParentElement, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{JobKind, JobView};

pub fn strip<F: Fn(&JobView) -> String>(jobs: &[JobView], disk: F, session: Entity<Session>) -> Option<impl IntoElement + use<F>> {
    if jobs.is_empty() {
        return None;
    }
    let t = tokens();
    let rows = jobs.iter().map(|job| {
        let mut facts = vec![format!("{:.0}%", job.fraction() * 100.0)];
        if job.progress.total > 0 {
            facts.push(format!("{} of {}", format::bytes(job.progress.scanned), format::bytes(job.progress.total)));
        }
        if let Some(left) = job.eta() {
            facts.push(format!("{} left", format::duration(left)));
        }
        let (id, session) = (job.id, session.clone());
        v_flex()
            .gap(px(6.))
            .child(
                h_flex()
                    .gap(px(16.))
                    .text_size(t.size_small)
                    .child(div().text_color(t.text).child(format!("Searching {}", disk(job))))
                    .child(div().text_color(t.text_secondary).child(facts.join("  ")))
                    .child(div().flex_1().min_w_0().truncate().text_color(t.text_secondary).child(job.current.clone()))
                    .child(TextButton::new(("search-stop", id.0 as usize), "Stop").on_click(move |_, _, cx| {
                        session.update(cx, |s, cx| s.cancel(id, cx));
                    })),
            )
            .child(loading_line(("search-progress", id.0 as usize)))
    });
    Some(v_flex().gap(px(10.)).children(rows))
}

/// The search jobs among the active ones.
pub fn running(active: impl Iterator<Item = JobView>) -> Vec<JobView> {
    active.filter(|j| j.kind == JobKind::Search).collect()
}
