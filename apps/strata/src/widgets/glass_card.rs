use crate::theme::tokens;
use gpui::{
    AnyElement, App, IntoElement, ParentElement, RenderOnce, SharedString, StyleRefinement, Styled,
    Window, div, prelude::FluentBuilder as _,
};
use gpui_component::{StyledExt as _, h_flex, v_flex};

/// Translucent navy panel with optional title row; the base of every dashboard block.
#[derive(IntoElement)]
pub struct GlassCard {
    title: Option<SharedString>,
    subtitle: Option<SharedString>,
    action: Option<AnyElement>,
    children: Vec<AnyElement>,
    style: StyleRefinement,
}

impl GlassCard {
    pub fn new() -> Self {
        Self { title: None, subtitle: None, action: None, children: Vec::new(), style: StyleRefinement::default() }
    }

    pub fn title(mut self, title: impl Into<SharedString>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn subtitle(mut self, subtitle: impl Into<SharedString>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }

    /// Element shown at the right end of the title row.
    pub fn action(mut self, action: impl IntoElement) -> Self {
        self.action = Some(action.into_any_element());
        self
    }
}

impl ParentElement for GlassCard {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.children.extend(elements);
    }
}

impl Styled for GlassCard {
    fn style(&mut self) -> &mut StyleRefinement {
        &mut self.style
    }
}

impl RenderOnce for GlassCard {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let has_header = self.title.is_some() || self.action.is_some();
        v_flex()
            .bg(t.card)
            .border_1()
            .border_color(t.card_border)
            .rounded(t.radius_card)
            .p(t.card_padding)
            .gap_4()
            .min_w_0()
            .refine_style(&self.style)
            .when(has_header, |el| {
                el.child(
                    h_flex()
                        .justify_between()
                        .items_start()
                        .gap_3()
                        .child(
                            v_flex()
                                .gap_0p5()
                                .min_w_0()
                                .when_some(self.title, |el, title| {
                                    el.child(
                                        div()
                                            .text_size(t.size_card_title)
                                            .font_weight(t.light)
                                            .text_color(t.text)
                                            .child(title),
                                    )
                                })
                                .when_some(self.subtitle, |el, sub| {
                                    el.child(div().text_size(t.size_caption).text_color(t.text_muted).truncate().child(sub))
                                }),
                        )
                        .children(self.action),
                )
            })
            .children(self.children)
    }
}
