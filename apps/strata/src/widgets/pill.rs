use crate::theme::tokens;
use gpui::{App, Hsla, IntoElement, ParentElement, RenderOnce, SharedString, Styled, Window, div, px};

/// Tiny rounded label (category, deleted/orphan state, disk id).
#[derive(IntoElement)]
pub struct Pill {
    text: SharedString,
    color: Hsla,
}

impl Pill {
    pub fn new(text: impl Into<SharedString>, color: Hsla) -> Self {
        Self { text: text.into(), color }
    }

    pub fn muted(text: impl Into<SharedString>) -> Self {
        Self::new(text, tokens().text_muted)
    }
}

impl RenderOnce for Pill {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        div()
            .flex_shrink_0()
            .px(px(7.))
            .py(px(1.))
            .rounded_full()
            .bg(self.color.opacity(0.14))
            .border_1()
            .border_color(self.color.opacity(0.35))
            .text_size(px(11.))
            .text_color(self.color)
            .child(self.text)
    }
}
