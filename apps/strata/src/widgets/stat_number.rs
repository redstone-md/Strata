use crate::theme::tokens;
use gpui::{
    App, IntoElement, ParentElement, Pixels, RenderOnce, SharedString, Styled, Window, div,
    prelude::FluentBuilder as _,
};
use gpui_component::{h_flex, v_flex};

/// Big thin number with a smaller unit and an optional caption ("650 GB").
#[derive(IntoElement)]
pub struct StatNumber {
    value: SharedString,
    unit: Option<SharedString>,
    caption: Option<SharedString>,
    size: Option<Pixels>,
}

impl StatNumber {
    pub fn new(value: impl Into<SharedString>) -> Self {
        Self { value: value.into(), unit: None, caption: None, size: None }
    }

    pub fn unit(mut self, unit: impl Into<SharedString>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    pub fn caption(mut self, caption: impl Into<SharedString>) -> Self {
        self.caption = Some(caption.into());
        self
    }

    pub fn size(mut self, size: Pixels) -> Self {
        self.size = Some(size);
        self
    }
}

impl RenderOnce for StatNumber {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let size = self.size.unwrap_or(t.size_number);
        v_flex()
            .gap_1()
            .child(
                h_flex()
                    .items_baseline()
                    .gap_1p5()
                    .child(
                        div()
                            .text_size(size)
                            .font_weight(t.thin)
                            .text_color(t.text)
                            .line_height(size * 1.1)
                            .child(self.value),
                    )
                    .when_some(self.unit, |el, unit| {
                        el.child(div().text_size(size * 0.42).font_weight(t.light).text_color(t.text_muted).child(unit))
                    }),
            )
            .when_some(self.caption, |el, c| el.child(div().text_size(t.size_caption).text_color(t.text_muted).child(c)))
    }
}
