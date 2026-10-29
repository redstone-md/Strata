//! One evidence disk on the dashboard: size, volumes, scan coverage, damage.

use crate::format;
use crate::session::{DiskSummary, Session};
use crate::theme::tokens;
use crate::widgets::{GlassCard, Glyph, GradientBar, StatNumber, glyph};
use gpui::{App, Entity, IntoElement, ParentElement, RenderOnce, Styled, Window, div, prelude::FluentBuilder as _, px};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{Sizable as _, h_flex, v_flex};

#[derive(IntoElement)]
pub struct DiskCard {
    disk: DiskSummary,
    session: Entity<Session>,
    busy: bool,
}

impl DiskCard {
    pub fn new(disk: DiskSummary, session: Entity<Session>, busy: bool) -> Self {
        Self { disk, session, busy }
    }
}

impl RenderOnce for DiskCard {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let d = &self.disk;
        let info = &d.record.info;
        let (size, unit) = format::bytes_parts(d.len());
        let scanned_bytes = (d.len() as f64 * d.scanned as f64) as u64;
        let id = d.id();
        let session = self.session.clone();
        let action = (!self.busy && !d.scan_complete).then(|| {
            Button::new(gpui::SharedString::from(format!("analyse-{id}")))
                .small()
                .primary()
                .label(if d.scanned > 0.0 { "Resume" } else { "Analyse" })
                .on_click(move |_, _, cx| session.update(cx, |s, cx| s.analyse(id, cx)))
        });
        let volumes = d.record.volumes.len();
        GlassCard::new()
            .title(info.label.clone())
            .subtitle(info.location.clone())
            .when_some(action, |c, a| c.action(a))
            .w(px(380.))
            .child(
                h_flex()
                    .justify_between()
                    .items_end()
                    .child(StatNumber::new(size).unit(unit).caption(format!(
                        "{volumes} volume{} · {:?}",
                        if volumes == 1 { "" } else { "s" },
                        info.kind
                    )))
                    .child(StatNumber::new(format::percent(d.scanned)).size(px(26.)).caption("scanned")),
            )
            .child(GradientBar::rainbow(d.scanned).height(px(10.)))
            .child(
                h_flex()
                    .gap_3()
                    .text_size(t.size_caption)
                    .text_color(t.text_muted)
                    .child(format!("{} scanned", format::bytes(scanned_bytes)))
                    .child(div().w(px(1.)).h(px(14.)).bg(t.glass_border))
                    .child(format!("{} left", format::bytes(d.len().saturating_sub(scanned_bytes)))),
            )
            .when(d.damaged > 0, |c| {
                c.child(
                    h_flex()
                        .gap_2()
                        .text_size(t.size_caption)
                        .text_color(t.orange)
                        .child(glyph(Glyph::TriangleAlert, px(14.), t.orange))
                        .child(format!("{} unreadable", format::bytes(d.damaged))),
                )
            })
            .when(d.record.volumes.is_empty(), |c| {
                c.child(v_flex().text_size(t.size_caption).text_color(t.text_dim).child("No partitions or filesystems recognised"))
            })
    }
}
