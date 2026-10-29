//! Side panel with everything known about one hit, plus copy-to-clipboard for the value.

use super::details::HitDetails;
use crate::format;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, FileTypeTile, GlassCard, Glyph, Pill, glyph};
use gpui::{
    App, ClickEvent, ClipboardItem, InteractiveElement as _, IntoElement, ParentElement, RenderOnce,
    SharedString, StatefulInteractiveElement as _, Styled, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{Icon, Sizable as _, h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::StoredHit;

#[derive(IntoElement)]
pub struct HitDetailPanel {
    hit: StoredHit,
    disk: String,
    on_close: ClickHandler,
}

impl HitDetailPanel {
    pub fn new(hit: StoredHit, disk: String, on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        Self { hit, disk, on_close: Rc::new(on_close) }
    }

    fn field(label: &'static str, value: impl Into<SharedString>) -> impl IntoElement {
        let t = tokens();
        v_flex()
            .gap_0p5()
            .child(div().text_size(t.size_caption).text_color(t.text_muted).child(label))
            .child(div().text_sm().text_color(t.text).child(value.into()))
    }
}

impl RenderOnce for HitDetailPanel {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let h = &self.hit;
        let value = h.hit.value.clone();
        let close = self.on_close.clone();
        let file = match (&h.file_path, &h.file_state) {
            (Some(p), Some(s)) => format!("{p}  ({s})"),
            (Some(p), None) => p.clone(),
            _ => "not attributed to a file".into(),
        };
        let mut card = GlassCard::new()
            .title(h.hit.label.clone())
            .subtitle(format!("{:?} · {}", h.hit.category, h.hit.detector))
            .action(
                div()
                    .id("detail-close")
                    .size(px(26.))
                    .rounded_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(|s| s.bg(t.glass_hover))
                    .child(glyph(Glyph::X, px(14.), t.text_muted))
                    .on_click(move |e, w, cx| close(e, w, cx)),
            )
            .w(px(400.))
            .flex_shrink_0()
            .h_full();
        card = card
            .child(
                v_flex()
                    .gap_2()
                    .p_3()
                    .rounded(t.radius_tile)
                    .bg(t.tile)
                    .border_1()
                    .border_color(t.card_border)
                    .child(
                        div()
                            .text_sm()
                            .font_family("Consolas")
                            .text_color(t.text)
                            .whitespace_normal()
                            .child(value.clone()),
                    )
                    .child(
                        h_flex().justify_end().child(
                            Button::new("copy-value")
                                .small()
                                .ghost()
                                .icon(Icon::new(Glyph::Copy))
                                .label("Copy value")
                                .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(value.clone()))),
                        ),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(Pill::new(format::percent(h.hit.confidence.get()), t.green))
                    .child(Pill::muted(self.disk.clone())),
            )
            .child(
                h_flex()
                    .gap_3()
                    .child(FileTypeTile::new(h.file_path.as_deref().map_or_else(|| "RAW".into(), format::file_kind)))
                    .child(Self::field("File", file)),
            )
            .child(
                h_flex()
                    .gap_6()
                    .child(Self::field("Disk offset", format::hex_offset(h.hit.offset)))
                    .child(Self::field("File offset", h.file_offset.map(format::hex_offset).unwrap_or_else(|| "—".into())))
                    .child(Self::field("Length", h.hit.len.to_string())),
            )
            .child(div().text_size(t.size_caption).text_color(t.text_muted).child("Details"))
            .child(
                div()
                    .id("detail-json")
                    .flex_1()
                    .min_h(px(80.))
                    .overflow_y_scroll()
                    .p_3()
                    .rounded(t.radius_tile)
                    .bg(t.tile)
                    .text_xs()
                    .font_family("Consolas")
                    .text_color(t.text_muted)
                    .whitespace_normal()
                    .child(HitDetails(&h.hit.details).pretty()),
            );
        card
    }
}
