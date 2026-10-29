use crate::theme::tokens;
use gpui::{App, IntoElement, ParentElement, RenderOnce, SharedString, Styled, Window, div, px};

/// Small state label. `outline` for neutral states (deleted, orphan), `inverted` for
/// warnings and failures — the monochrome replacement for red.
#[derive(IntoElement)]
pub struct Badge {
    text: SharedString,
    inverted: bool,
}

impl Badge {
    pub fn outline(text: impl Into<SharedString>) -> Self {
        Self { text: text.into(), inverted: false }
    }

    pub fn inverted(text: impl Into<SharedString>) -> Self {
        Self { text: text.into(), inverted: true }
    }
}

impl RenderOnce for Badge {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let base = div()
            .flex_shrink_0()
            .px(px(5.))
            .h(px(18.))
            .flex()
            .items_center()
            .rounded(t.radius)
            .border_1()
            .text_size(t.size_small)
            .line_height(px(16.));
        let styled = if self.inverted {
            base.bg(t.text).border_color(t.text).text_color(t.ink)
        } else {
            base.border_color(t.text_secondary).text_color(t.text)
        };
        styled.child(self.text)
    }
}
