//! Background jobs in the "uploading files" style, with an overall progress panel.

use crate::format;
use crate::session::{Session, Snapshot};
use crate::theme::tokens;
use crate::widgets::{GlassCard, Glyph, GradientBar, ProgressRow, RowStatus, glyph};
use gpui::{
    App, Entity, InteractiveElement as _, StatefulInteractiveElement as _, IntoElement, ParentElement, RenderOnce, Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::spinner::Spinner;
use gpui_component::{h_flex, v_flex};
use strata_workbench::{JobKind, JobState, JobView};

const MAX_ROWS: usize = 8;

#[derive(IntoElement)]
pub struct JobsCard {
    snapshot: Snapshot,
    session: Entity<Session>,
}

impl JobsCard {
    pub fn new(snapshot: Snapshot, session: Entity<Session>) -> Self {
        Self { snapshot, session }
    }

    fn row(&self, job: &JobView) -> ProgressRow {
        let (kind, verb) = match job.kind {
            JobKind::IndexFiles => ("IDX", "Index files"),
            JobKind::Scan => ("SCN", "Deep scan"),
            JobKind::ClassifyFiles => ("TYP", "Classify files"),
            JobKind::Carve => ("CRV", "Carve free space"),
            JobKind::CheckBalances => ("BAL", "Check balances"),
        };
        let status = match &job.state {
            JobState::Queued => RowStatus::Queued,
            JobState::Running => RowStatus::Running,
            JobState::Done(_) => RowStatus::Done,
            JobState::Failed(e) => RowStatus::Failed(e.clone().into()),
            JobState::Cancelled => RowStatus::Cancelled,
        };
        let p = &job.progress;
        let detail = match &job.state {
            JobState::Done(msg) => msg.clone(),
            _ if p.total > 0 => format!("{} / {}", format::bytes(p.scanned), format::bytes(p.total)),
            _ => String::new(),
        };
        let session = self.session.clone();
        let id = job.id;
        ProgressRow::new(("job", id.0 as usize), kind, format!("{verb} · {}", self.snapshot.disk_label(job.evidence)))
            .detail(detail)
            .progress(job.fraction(), status)
            .on_cancel(move |_, _, cx| session.update(cx, |s, cx| s.cancel(id, cx)))
    }

    /// Average scan coverage over all disks, shown when nothing is running.
    fn coverage(&self) -> f32 {
        let disks = &self.snapshot.disks;
        if disks.is_empty() {
            return 0.0;
        }
        disks.iter().map(|d| d.scanned).sum::<f32>() / disks.len() as f32
    }

    fn summary_panel(&self) -> impl IntoElement {
        let t = tokens();
        let active = self.snapshot.active_jobs().last().cloned();
        let (head, fraction, caption) = match (self.snapshot.overall_progress(), active) {
            (Some(f), Some(job)) => (
                h_flex().gap_2().child(Spinner::new().color(t.blue)).child("Scanning").into_any_element(),
                f,
                format!("{} hits · {}/s", job.progress.hits, format::bytes(job.progress.bytes_per_sec as u64)),
            ),
            _ => (
                h_flex().gap_2().child(glyph(Glyph::Check, px(14.), t.green)).child("Idle").into_any_element(),
                self.coverage(),
                format!("{} findings in case · disk coverage", self.snapshot.total_hits),
            ),
        };
        v_flex()
            .gap_3()
            .p_4()
            .rounded(t.radius_control)
            .bg(t.tile)
            .border_1()
            .border_color(t.card_border)
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_sm().text_color(t.text_muted).child(head))
                    .child(div().text_size(px(30.)).font_weight(t.thin).text_color(t.text).child(format::percent(fraction))),
            )
            .child(GradientBar::scan(fraction).height(px(10.)))
            .child(div().text_size(t.size_caption).text_color(t.text_muted).child(caption))
    }
}

impl RenderOnce for JobsCard {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let active = self.snapshot.active_jobs().count();
        let rows: Vec<_> = self.snapshot.jobs.iter().rev().take(MAX_ROWS).map(|j| self.row(j)).collect();
        let empty = rows.is_empty();
        GlassCard::new()
            .title("Jobs")
            .subtitle(format!("{active} active · {} total", self.snapshot.jobs.len()))
            .w(px(400.))
            .flex_shrink_0()
            .child(
                v_flex()
                    .id("jobs")
                    .gap_3()
                    .max_h(px(420.))
                    .overflow_y_scroll()
                    .children(rows)
                    .when(empty, |el| {
                        el.child(
                            div()
                                .text_sm()
                                .text_color(t.text_dim)
                                .child("No jobs yet. Analyse a disk to start indexing and scanning."),
                        )
                    }),
            )
            .child(self.summary_panel())
    }
}
