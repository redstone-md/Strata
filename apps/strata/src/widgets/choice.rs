//! A row of mutually exclusive options set as plain words: the chosen one is white with a 1px
//! outline, the others secondary until hovered.

use crate::theme::tokens;
use gpui::{
    App, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, px,
};
use gpui_component::h_flex;
use std::rc::Rc;

type SelectHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct Choice {
    id: SharedString,
    options: Vec<SharedString>,
    selected: usize,
    on_select: SelectHandler,
}

impl Choice {
    pub fn new(id: impl Into<SharedString>, options: Vec<SharedString>, selected: usize, on_select: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        Self { id: id.into(), options, selected, on_select: Rc::new(on_select) }
    }
}

impl RenderOnce for Choice {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        h_flex().gap(px(2.)).children(self.options.into_iter().enumerate().map(|(i, label)| {
            let on = i == self.selected;
            let handler = self.on_select.clone();
            div()
                .id(ElementId::Name(format!("{}-{i}", self.id).into()))
                .h(px(26.))
                .px(px(8.))
                .flex()
                .items_center()
                .rounded(t.radius)
                .border_1()
                .text_size(t.size_body)
                .cursor_pointer()
                .border_color(if on { t.text_secondary } else { gpui::transparent_black() })
                .text_color(if on { t.emphasis } else { t.text_secondary })
                .hover(|s| s.text_color(t.emphasis))
                .child(label)
                .on_click(move |_, w, cx| handler(i, w, cx))
        }))
    }
}
