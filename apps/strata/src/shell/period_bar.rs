//! The period of interest: a strip under the command bar, opened from the period button in
//! the bar. Two fields (`2008`, `2013-06`, `2013-06-30`; either may stay empty) narrow every
//! list in the case: findings by the dates of their files, the timeline, mail, accounts and
//! leads. Things without a date are always shown.

use crate::theme::tokens;
use crate::widgets::{ClickHandler, Field, TextButton};
use gpui::{App, Entity, IntoElement, ParentElement, RenderOnce, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::input::InputState;

#[derive(IntoElement)]
pub struct PeriodBar {
    from: Entity<InputState>,
    to: Entity<InputState>,
    error: Option<String>,
    on_apply: ClickHandler,
    on_clear: ClickHandler,
}

impl PeriodBar {
    pub fn new(from: &Entity<InputState>, to: &Entity<InputState>, error: Option<String>, on_apply: ClickHandler, on_clear: ClickHandler) -> Self {
        Self { from: from.clone(), to: to.clone(), error, on_apply, on_clear }
    }
}

impl RenderOnce for PeriodBar {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let (on_apply, on_clear) = (self.on_apply.clone(), self.on_clear.clone());
        h_flex()
            .w_full()
            .h(px(48.))
            .flex_shrink_0()
            .pl(t.sidebar_width + t.gutter)
            .gap(px(12.))
            .border_b_1()
            .border_color(t.rule)
            .text_size(t.size_body)
            .text_color(t.text_secondary)
            .child("Only show what happened from")
            .child(Field::new(&self.from).width(px(120.)))
            .child("to")
            .child(Field::new(&self.to).width(px(120.)))
            .child(TextButton::new("period-apply", "Apply").on_click(move |e, w, cx| on_apply(e, w, cx)))
            .child(TextButton::new("period-clear", "All dates").on_click(move |e, w, cx| on_clear(e, w, cx)))
            .children(self.error.map(|e| div().text_color(t.emphasis).child(e)))
            .child(div().flex_1())
            .child(div().pr(t.gutter).child("Undated findings, such as those in free space, are always shown."))
    }
}
