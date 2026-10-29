//! Evidence warnings: disks whose evidence does not look complete (wiped, reinstalled, not
//! fully read, barely used) with their most severe observations. Each row opens Disks.

use super::Overview;
use crate::nav::{Navigate, Screen};
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::views::disks::consistency::severity_badge;
use crate::widgets::{Badge, Section};
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement, SharedString, StatefulInteractiveElement as _, Styled, div, px,
};
use gpui_component::{h_flex, v_flex};
use std::collections::HashMap;
use strata_workbench::{Assessment, EvidenceId, Severity, VerdictKind};

/// Observations listed per disk; the rest are on the Disks screen.
const PER_DISK: usize = 3;

/// `None` when no disk needs a closer look.
pub fn section(snapshot: &Snapshot, assessments: &HashMap<EvidenceId, Assessment>, cx: &mut Context<Overview>) -> Option<impl IntoElement> {
    let t = tokens();
    let rows: Vec<_> = snapshot
        .disks
        .iter()
        .filter_map(|d| Some((d, assessments.get(&d.id()).filter(|a| a.needs_attention())?)))
        .map(|(d, a)| {
            let verdict = match a.verdict.kind {
                VerdictKind::NormallyUsed => Badge::outline(a.verdict.headline.clone()),
                _ => Badge::inverted(a.verdict.headline.clone()),
            };
            let lines = a.at_least(Severity::Warning).take(PER_DISK).map(|o| {
                h_flex()
                    .gap(px(8.))
                    .min_w_0()
                    .child(h_flex().w(px(64.)).flex_shrink_0().children(severity_badge(o.severity)))
                    .child(div().min_w_0().truncate().text_size(t.size_body).text_color(t.text).child(o.title.clone()))
            });
            v_flex()
                .id(SharedString::from(format!("consistency-{}", d.id())))
                .gap(px(6.))
                .py(px(8.))
                .px(px(8.))
                .border_b_1()
                .border_color(t.row_rule)
                .cursor_pointer()
                .hover(|s| s.bg(t.hover))
                .child(
                    h_flex()
                        .gap(px(12.))
                        .min_w_0()
                        .child(div().text_size(t.size_body).font_weight(t.semibold).text_color(t.emphasis).truncate().child(d.record.info.label.clone()))
                        .child(verdict),
                )
                .children(lines)
                .on_click(cx.listener(|_, _, _, cx| cx.emit(Navigate::to(Screen::Disks))))
        })
        .collect();
    (!rows.is_empty()).then(|| {
        Section::new("Evidence warnings")
            .note("disks whose evidence may be incomplete; details on Disks")
            .child(v_flex().border_t_1().border_color(t.row_rule).children(rows))
    })
}
