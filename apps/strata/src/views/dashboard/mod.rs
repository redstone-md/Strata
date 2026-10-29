//! Dashboard: disks, finding counters and jobs at a glance.

mod disk_card;
mod jobs_card;

use crate::categories::FINDINGS;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{GlassCard, StatNumber, glyph};
use disk_card::DiskCard;
use gpui::{Context, Entity, IntoElement, ParentElement, Render, Styled, Subscription, Window, div, px};
use gpui_component::{h_flex, v_flex};
use jobs_card::JobsCard;

pub struct Dashboard {
    session: Entity<Session>,
    _observe: Subscription,
}

impl Dashboard {
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&session, |_, _, cx| cx.notify());
        Self { session, _observe: observe }
    }

    fn findings(&self, cx: &Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot();
        let tiles = FINDINGS.iter().map(|c| {
            let n = snapshot.count(c.category);
            let accent = if n > 0 { t.blue } else { t.text_dim };
            GlassCard::new().w(px(176.)).gap_3().child(
                v_flex()
                    .gap_3()
                    .child(
                        div()
                            .size(px(34.))
                            .rounded(t.radius_tile)
                            .bg(accent.opacity(0.14))
                            .border_1()
                            .border_color(accent.opacity(0.3))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(glyph(c.glyph, px(16.), accent)),
                    )
                    .child(StatNumber::new(n.to_string()).size(px(32.)).caption(c.label)),
            )
        });
        v_flex()
            .gap_3()
            .child(div().text_size(t.size_card_title).font_weight(t.light).text_color(t.text).child("Findings"))
            .child(h_flex().flex_wrap().gap(t.gap).children(tiles))
    }
}

impl Render for Dashboard {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let session = self.session.read(cx);
        let snapshot = session.snapshot().clone();
        let busy = |id| snapshot.active_jobs().any(|j| j.evidence == id);
        let disks: Vec<_> =
            snapshot.disks.iter().map(|d| DiskCard::new(d.clone(), self.session.clone(), busy(d.id()))).collect();
        let no_disks = disks.is_empty().then(|| {
            GlassCard::new()
                .title("No evidence yet")
                .subtitle("Open Evidence in the rail to add a disk image or a physical drive")
                .w(px(380.))
        });
        v_flex()
            .gap(t.gap_lg)
            .child(
                v_flex()
                    .gap_1()
                    .child(div().text_sm().text_color(t.text_muted).child("Case"))
                    .child(
                        div()
                            .text_size(t.size_hero)
                            .font_weight(t.thin)
                            .text_color(t.text)
                            .child(session.case_name()),
                    ),
            )
            .child(
                h_flex()
                    .items_start()
                    .gap(t.gap_lg)
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap(t.gap_lg)
                            .child(h_flex().flex_wrap().gap(t.gap).children(disks).children(no_disks))
                            .child(self.findings(cx)),
                    )
                    .child(JobsCard::new(snapshot.clone(), self.session.clone())),
            )
    }
}
