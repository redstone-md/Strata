use crate::theme::tokens;
use gpui::{
    AnyElement, App, Div, IntoElement, ParentElement, RenderOnce, SharedString, StyleRefinement, Styled, Window, div,
    px,
};
use gpui_component::{StyledExt as _, h_flex, v_flex};

/// A titled block of a page. No box: the title, then the content, separated from the next
/// section by whitespace.
#[derive(IntoElement)]
pub struct Section {
    title: SharedString,
    note: Option<SharedString>,
    aside: Option<AnyElement>,
    children: Vec<AnyElement>,
    style: StyleRefinement,
}

impl Section {
    pub fn new(title: impl Into<SharedString>) -> Self {
        Self { title: title.into(), note: None, aside: None, children: Vec::new(), style: StyleRefinement::default() }
    }

    /// Secondary text right after the title (a count, a scope).
    pub fn note(mut self, note: impl Into<SharedString>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Element at the right end of the title line.
    pub fn aside(mut self, aside: impl IntoElement) -> Self {
        self.aside = Some(aside.into_any_element());
        self
    }
}

impl ParentElement for Section {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.children.extend(elements);
    }
}

impl Styled for Section {
    fn style(&mut self) -> &mut StyleRefinement {
        &mut self.style
    }
}

impl RenderOnce for Section {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let title = h_flex()
            .gap_3()
            .items_baseline()
            .min_w_0()
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child(self.title))
            .children(self.note.map(|n| div().text_size(t.size_body).text_color(t.text_secondary).truncate().child(n)));
        v_flex()
            .gap(px(12.))
            .min_w_0()
            .refine_style(&self.style)
            .child(h_flex().justify_between().items_center().gap_4().min_h(px(26.)).child(title).children(self.aside))
            .children(self.children)
    }
}

/// 1px horizontal rule.
pub fn rule() -> Div {
    div().w_full().h(px(1.)).flex_shrink_0().bg(tokens().rule)
}
