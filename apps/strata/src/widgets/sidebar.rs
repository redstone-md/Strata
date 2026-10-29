use super::{Glyph, glyph};
use crate::theme::tokens;
use gpui::{
    AnyElement, App, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;

/// One navigation entry. `key` is handed back to the select handler.
#[derive(Clone)]
pub struct NavItem {
    pub key: usize,
    pub glyph: Glyph,
    pub label: SharedString,
}

type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

/// Left navigation: text items with small line icons; the active one is white with a 2px bar
/// on the left edge.
#[derive(IntoElement)]
pub struct Sidebar {
    active: usize,
    items: Vec<NavItem>,
    footer: Vec<NavItem>,
    on_select: SelectHandler,
}

impl Sidebar {
    pub fn new(active: usize, on_select: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        Self { active, items: Vec::new(), footer: Vec::new(), on_select: Rc::new(on_select) }
    }

    pub fn items(mut self, items: Vec<NavItem>) -> Self {
        self.items = items;
        self
    }

    pub fn footer(mut self, items: Vec<NavItem>) -> Self {
        self.footer = items;
        self
    }

    fn item(&self, item: &NavItem) -> AnyElement {
        let t = tokens();
        let active = item.key == self.active;
        let handler = self.on_select.clone();
        let key = item.key;
        let color = if active { t.emphasis } else { t.text_secondary };
        h_flex()
            .id(SharedString::from(format!("nav-{}", item.key)))
            .relative()
            .h(px(32.))
            .pl(px(20.))
            .pr(px(12.))
            .gap(px(10.))
            .cursor_pointer()
            .text_size(t.size_body)
            .text_color(color)
            .when(active, |el| el.child(div().absolute().left_0().top(px(6.)).w(px(2.)).h(px(20.)).bg(t.emphasis)))
            .when(!active, |el| el.hover(|s| s.text_color(t.text)))
            .child(glyph(item.glyph, px(16.), color))
            .child(item.label.clone())
            .on_click(move |_, window, cx| handler(key, window, cx))
            .into_any_element()
    }
}

impl RenderOnce for Sidebar {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        v_flex()
            .w(t.sidebar_width)
            .h_full()
            .flex_shrink_0()
            .justify_between()
            .pt(px(12.))
            .pb(px(12.))
            .bg(t.sidebar)
            .child(v_flex().children(self.items.iter().map(|i| self.item(i))))
            .child(v_flex().children(self.footer.iter().map(|i| self.item(i))))
    }
}
