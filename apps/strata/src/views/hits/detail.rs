//! Side panel for one finding: what it is, its value with Copy, then the typed detail tree.

use super::detail_tree::DetailTree;
use crate::categories;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, TextButton, mono, rule};
use gpui::{
    App, ClickEvent, ClipboardItem, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::StoredHit;

const WIDTH: f32 = 480.;

#[derive(IntoElement)]
pub struct HitDetailPanel {
    hit: StoredHit,
    tree: DetailTree,
    on_close: ClickHandler,
    /// Extra actions next to Copy value (export of carved data or an archive member, the
    /// mail of an address).
    actions: Vec<(SharedString, ClickHandler)>,
    note: Option<SharedString>,
}

impl HitDetailPanel {
    pub fn new(hit: StoredHit, tree: DetailTree, on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        Self { hit, tree, on_close: Rc::new(on_close), actions: Vec::new(), note: None }
    }

    pub fn action(mut self, label: impl Into<SharedString>, handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.actions.push((label.into(), Rc::new(handler)));
        self
    }

    pub fn note(mut self, note: Option<SharedString>) -> Self {
        self.note = note;
        self
    }
}

impl RenderOnce for HitDetailPanel {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let h = &self.hit;
        let value = h.hit.value.clone();
        let close = self.on_close.clone();
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex()
                    .p(px(20.))
                    .pb(px(12.))
                    .gap(px(12.))
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
                    .child(mono().text_size(t.size_body).text_color(t.emphasis).whitespace_normal().child(value.clone()))
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .child(
                                TextButton::new("copy-value", "Copy value")
                                    .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(value.clone()))),
                            )
                            .children(self.actions.into_iter().enumerate().map(|(i, (label, handler))| {
                                TextButton::new(("finding-action", i), label).on_click(move |e, w, cx| handler(e, w, cx))
                            })),
                    )
                    .children(self.note.map(|n| div().text_size(t.size_body).text_color(t.text).whitespace_normal().child(n))),
            )
            .child(rule())
            .child(div().id("detail-tree").flex_1().min_h_0().overflow_y_scroll().px(px(12.)).py(px(8.)).child(self.tree))
    }
}
