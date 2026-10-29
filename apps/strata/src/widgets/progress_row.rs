use super::{ClickHandler, FileTypeTile, Glyph, GradientBar, glyph};
use crate::format;
use crate::theme::tokens;
use gpui::{
    App, ClickEvent, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce,
    SharedString, StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;

/// What a [`ProgressRow`] shows at its right edge.
#[derive(Clone, PartialEq)]
pub enum RowStatus {
    Queued,
    Running,
    Done,
    Failed(SharedString),
    Cancelled,
}

/// "Uploading files" style row: type tile, name + detail, thin white bar, status badge.
#[derive(IntoElement)]
pub struct ProgressRow {
    id: ElementId,
    kind: SharedString,
    name: SharedString,
    detail: SharedString,
    fraction: f32,
    status: RowStatus,
    on_cancel: Option<ClickHandler>,
}

impl ProgressRow {
    pub fn new(id: impl Into<ElementId>, kind: impl Into<SharedString>, name: impl Into<SharedString>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            name: name.into(),
            detail: SharedString::default(),
            fraction: 0.0,
            status: RowStatus::Queued,
            on_cancel: None,
        }
    }

    pub fn detail(mut self, detail: impl Into<SharedString>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn progress(mut self, fraction: f32, status: RowStatus) -> Self {
        self.fraction = fraction;
        self.status = status;
        self
    }

    pub fn on_cancel(mut self, handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_cancel = Some(Rc::new(handler));
        self
    }

    fn badge(&self) -> gpui::AnyElement {
        let t = tokens();
        let text = |s: String, color| div().text_size(t.size_caption).text_color(color).child(s);
        match &self.status {
            RowStatus::Done => div()
                .size(px(20.))
                .rounded_full()
                .bg(t.green)
                .flex()
                .items_center()
                .justify_center()
                .child(glyph(Glyph::Check, px(12.), gpui::white()))
                .into_any_element(),
            RowStatus::Failed(_) => text("failed".into(), t.red).into_any_element(),
            RowStatus::Cancelled => text("cancelled".into(), t.text_dim).into_any_element(),
            RowStatus::Queued => text("queued".into(), t.text_muted).into_any_element(),
            RowStatus::Running => text(format::percent(self.fraction), t.text).into_any_element(),
        }
    }
}

impl RenderOnce for ProgressRow {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let badge = self.badge();
        let active = matches!(self.status, RowStatus::Running | RowStatus::Queued);
        let detail = match &self.status {
            RowStatus::Failed(msg) => msg.clone(),
            _ => self.detail.clone(),
        };
        let cancel = self.on_cancel.filter(|_| active).map(|handler| {
            div()
                .id(self.id.clone())
                .size(px(22.))
                .rounded_full()
                .flex()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .hover(|s| s.bg(t.glass_hover))
                .child(glyph(Glyph::X, px(13.), t.text_muted))
                .on_click(move |e, w, cx| handler(e, w, cx))
        });
        h_flex()
            .gap_3()
            .py_1()
            .child(FileTypeTile::new(self.kind))
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_1p5()
                    .child(
                        h_flex()
                            .justify_between()
                            .gap_2()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .min_w_0()
                                    .child(div().text_sm().text_color(t.text).truncate().child(self.name))
                                    .child(div().text_size(t.size_caption).text_color(t.text_muted).truncate().child(detail)),
                            )
                            .child(h_flex().gap_1().flex_shrink_0().child(badge).children(cancel)),
                    )
                    .when(self.status != RowStatus::Cancelled, |el| {
                        el.child(GradientBar::solid(self.fraction, t.text).height(px(4.)))
                    }),
            )
    }
}
