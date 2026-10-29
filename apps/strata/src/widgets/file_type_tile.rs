use crate::theme::tokens;
use gpui::{App, IntoElement, ParentElement, RenderOnce, SharedString, Styled, Window, div, px};

/// Small dark tile with a short type label (DAT, ZIP, DB…).
#[derive(IntoElement)]
pub struct FileTypeTile {
    label: SharedString,
}

impl FileTypeTile {
    pub fn new(label: impl Into<SharedString>) -> Self {
        Self { label: label.into() }
    }
}

impl RenderOnce for FileTypeTile {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        div()
            .flex_shrink_0()
            .size(px(40.))
            .rounded(t.radius_tile)
            .bg(t.tile)
            .border_1()
            .border_color(t.card_border)
            .flex()
            .items_center()
            .justify_center()
            .text_size(px(10.))
            .text_color(t.text_muted)
            .child(self.label)
    }
}
