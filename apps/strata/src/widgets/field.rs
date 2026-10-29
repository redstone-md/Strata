use crate::theme::tokens;
use gpui::{
    App, Entity, IntoElement, ParentElement, Pixels, RenderOnce, SharedString, Styled, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::h_flex;
use gpui_component::input::{Input, InputState};

/// Flat single-line text field: 1px rule border, 3px radius, optional plain trailing hint.
#[derive(IntoElement)]
pub struct Field {
    state: Entity<InputState>,
    hint: Option<SharedString>,
    width: Option<Pixels>,
    data: bool,
}

impl Field {
    pub fn new(state: &Entity<InputState>) -> Self {
        Self { state: state.clone(), hint: None, width: None, data: false }
    }

    /// Plain secondary text at the right end, e.g. a shortcut.
    pub fn hint(mut self, hint: impl Into<SharedString>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn width(mut self, width: Pixels) -> Self {
        self.width = Some(width);
        self
    }

    /// The value is data (a path, a URL): render it in the data face.
    pub fn data(mut self) -> Self {
        self.data = true;
        self
    }
}

impl RenderOnce for Field {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let input = div()
            .flex_1()
            .min_w_0()
            .when(self.data, |d| d.font_family(t.font_data))
            .child(Input::new(&self.state).appearance(false));
        let field = h_flex()
            .h(px(28.))
            .pl(px(4.))
            .pr(px(10.))
            .gap_2()
            .rounded(t.radius)
            .border_1()
            .border_color(t.rule)
            .bg(t.ground)
            .text_size(t.size_body)
            .child(input)
            .children(self.hint.map(|h| div().flex_shrink_0().text_size(t.size_small).text_color(t.text_secondary).child(h)));
        match self.width {
            Some(w) => field.w(w),
            None => field.w_full(),
        }
    }
}
