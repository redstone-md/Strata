use super::{Glyph, glyph};
use crate::theme::tokens;
use gpui::{
    AnyElement, App, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, linear_color_stop, linear_gradient, px,
};
use gpui_component::v_flex;
use std::rc::Rc;

/// One rail button. `key` is handed back to the select handler.
#[derive(Clone)]
pub struct RailItem {
    pub key: usize,
    pub glyph: Glyph,
    pub label: SharedString,
}

type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

/// Narrow vertical navigation: logo tile, grouped icon buttons, footer buttons.
#[derive(IntoElement)]
pub struct IconRail {
    active: usize,
    groups: Vec<Vec<RailItem>>,
    footer: Vec<RailItem>,
    on_select: SelectHandler,
}

impl IconRail {
    pub fn new(active: usize, on_select: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        Self { active, groups: Vec::new(), footer: Vec::new(), on_select: Rc::new(on_select) }
    }

    pub fn group(mut self, items: Vec<RailItem>) -> Self {
        self.groups.push(items);
        self
    }

    pub fn footer(mut self, items: Vec<RailItem>) -> Self {
        self.footer = items;
        self
    }

    fn logo() -> impl IntoElement {
        let t = tokens();
        div()
            .size(px(44.))
            .rounded(t.radius_control)
            .bg(linear_gradient(135., linear_color_stop(t.blue, 0.), linear_color_stop(t.indigo, 1.)))
            .shadow(vec![gpui::BoxShadow {
                color: t.blue.opacity(0.45),
                offset: gpui::point(px(0.), px(6.)),
                blur_radius: px(24.),
                spread_radius: px(0.),
                inset: false,
            }])
            .flex()
            .items_center()
            .justify_center()
            .child(glyph(Glyph::Layers, px(22.), gpui::white()))
    }

    fn separator() -> impl IntoElement {
        div().w(px(28.)).h(px(1.)).bg(tokens().separator)
    }

    fn button(&self, item: &RailItem) -> AnyElement {
        let t = tokens();
        let active = item.key == self.active;
        let handler = self.on_select.clone();
        let key = item.key;
        let base = div()
            .id(SharedString::from(format!("rail-{}", item.label)))
            .size(px(44.))
            .rounded(t.radius_control)
            .flex()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .border_1();
        let styled = if active {
            base.bg(t.glass_active).border_color(t.glass_border_strong)
        } else {
            base.border_color(gpui::transparent_black()).hover(|s| s.bg(t.glass_hover))
        };
        styled
            .child(glyph(item.glyph, px(20.), if active { t.text } else { t.text_muted }))
            .on_click(move |_, window, cx| handler(key, window, cx))
            .into_any_element()
    }
}

impl RenderOnce for IconRail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let mut top = v_flex().items_center().gap_3().child(Self::logo());
        for group in &self.groups {
            top = top.child(Self::separator());
            for item in group {
                top = top.child(self.button(item));
            }
        }
        let bottom = v_flex().items_center().gap_3().children(self.footer.iter().map(|i| self.button(i)));
        v_flex()
            .w(t.rail_width)
            .h_full()
            .flex_shrink_0()
            .items_center()
            .justify_between()
            .py_5()
            .border_r_1()
            .border_color(t.separator)
            .bg(t.glass)
            .child(top)
            .child(bottom)
    }
}
