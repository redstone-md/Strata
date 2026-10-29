use super::{Glyph, glyph};
use crate::theme::tokens;
use gpui::{App, Entity, IntoElement, ParentElement, Pixels, RenderOnce, SharedString, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::input::{Input, InputState};

/// Rounded glass text field with a leading icon and an optional keyboard-hint chip.
#[derive(IntoElement)]
pub struct SearchField {
    state: Entity<InputState>,
    glyph: Glyph,
    hint: Option<SharedString>,
    width: Option<Pixels>,
}

impl SearchField {
    pub fn new(state: &Entity<InputState>) -> Self {
        Self { state: state.clone(), glyph: Glyph::Search, hint: None, width: None }
    }

    pub fn glyph(mut self, glyph: Glyph) -> Self {
        self.glyph = glyph;
        self
    }

    pub fn hint(mut self, hint: impl Into<SharedString>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn width(mut self, width: Pixels) -> Self {
        self.width = Some(width);
        self
    }
}

impl RenderOnce for SearchField {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let chip = self.hint.map(|hint| {
            div()
                .flex_shrink_0()
                .px(px(7.))
                .py(px(2.))
                .rounded(px(6.))
                .border_1()
                .border_color(t.glass_border)
                .bg(t.glass)
                .text_size(px(11.))
                .text_color(t.text_muted)
                .child(hint)
        });
        let field = h_flex()
            .h(px(44.))
            .px_4()
            .gap_2()
            .rounded(t.radius_control)
            .bg(t.glass)
            .border_1()
            .border_color(t.glass_border)
            .child(glyph(self.glyph, px(16.), t.text_muted))
            .child(div().flex_1().min_w_0().child(Input::new(&self.state).appearance(false)))
            .children(chip);
        match self.width {
            Some(w) => field.w(w),
            None => field.w_full(),
        }
    }
}
