//! Side panel with everything known about one hit, plus copy-to-clipboard for the value.

use super::details::HitDetails;
use crate::categories;
use crate::format;
use crate::theme::tokens;
use crate::widgets::{Badge, ClickHandler, TextButton, mono, rule};
use gpui::{
    App, ClickEvent, ClipboardItem, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::StoredHit;

const WIDTH: f32 = 400.;

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

    /// Label above value; `data` values use the data face.
    fn field(label: &'static str, value: impl Into<SharedString>, data: bool) -> impl IntoElement {
        let t = tokens();
        let value = div().text_size(t.size_body).text_color(t.text).whitespace_normal().child(value.into());
        v_flex()
            .gap(px(2.))
            .min_w_0()
            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(label))
            .child(if data { value.font_family(t.font_data) } else { value })
    }
}

impl RenderOnce for HitDetailPanel {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let h = &self.hit;
        let value = h.hit.value.clone();
        let close = self.on_close.clone();
        let state = h.file_state.as_deref().filter(|s| matches!(*s, "Deleted" | "Orphan")).map(|s| Badge::outline(s.to_lowercase()));
        let file = match &h.file_path {
            Some(path) => mono().child(path.clone()),
            None => div().text_color(t.text_secondary).child("Not inside a known file (raw sectors)"),
        };
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .p(px(20.))
            .gap(px(16.))
            .child(
                h_flex()
                    .justify_between()
                    .items_start()
                    .child(
                        v_flex()
                            .gap(px(2.))
                            .min_w_0()
                            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child(h.hit.label.clone()))
                            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(format!(
                                "{}, found by {}",
                                categories::label(h.hit.category),
                                h.hit.detector
                            ))),
                    )
                    .child(TextButton::new("detail-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
            )
            .child(
                v_flex()
                    .gap(px(8.))
                    .child(mono().text_size(t.size_body).text_color(t.emphasis).whitespace_normal().child(value.clone()))
                    .child(h_flex().child(
                        TextButton::new("copy-value", "Copy value")
                            .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(value.clone()))),
                    )),
            )
            .child(rule())
            .child(
                v_flex()
                    .gap(px(4.))
                    .child(div().text_size(t.size_small).text_color(t.text_secondary).child("File"))
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .items_start()
                            .children(state)
                            .child(file.min_w_0().text_size(t.size_body).whitespace_normal()),
                    ),
            )
            .child(
                h_flex()
                    .gap(px(24.))
                    .child(Self::field("Disk", self.disk.clone(), false))
                    .child(Self::field("Disk offset", format::hex_offset(h.hit.offset), true))
                    .child(Self::field("File offset", h.file_offset.map(format::hex_offset).unwrap_or_else(|| "none".into()), true)),
            )
            .child(
                h_flex()
                    .gap(px(24.))
                    .child(Self::field("Length", format::count(h.hit.len as u64, "byte", "bytes"), false))
                    .child(Self::field("Confidence", format::percent(h.hit.confidence.get()), false)),
            )
            .child(rule())
            .child(div().text_size(t.size_small).text_color(t.text_secondary).child("Details"))
            .child(
                mono()
                    .id("detail-json")
                    .flex_1()
                    .min_h(px(80.))
                    .overflow_y_scroll()
                    .text_size(t.size_small)
                    .text_color(t.text)
                    .whitespace_normal()
                    .child(HitDetails(&h.hit.details).pretty()),
            )
    }
}
