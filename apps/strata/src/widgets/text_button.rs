use super::ClickHandler;
use crate::theme::tokens;
use gpui::{
    App, ClickEvent, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, px,
};
use std::rc::Rc;

/// Plain text button: no fill until hovered, 3px radius. `strong` raises it to white for the
/// one primary action in a group.
#[derive(IntoElement)]
pub struct TextButton {
    id: ElementId,
    label: SharedString,
    strong: bool,
    on_click: Option<ClickHandler>,
}

impl TextButton {
    pub fn new(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Self {
        Self { id: id.into(), label: label.into(), strong: false, on_click: None }
    }

    pub fn strong(mut self) -> Self {
        self.strong = true;
        self
    }

    pub fn on_click(mut self, handler: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_click = Some(Rc::new(handler));
        self
    }
}

impl RenderOnce for TextButton {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let base = div()
            .id(self.id)
            .flex_shrink_0()
            .h(px(26.))
            .px(px(8.))
            .flex()
            .items_center()
            .rounded(t.radius)
            .border_1()
            .text_size(t.size_body)
            .child(self.label);
        match self.on_click {
            Some(handler) => base
                .border_color(t.rule)
                .text_color(if self.strong { t.emphasis } else { t.text })
                .cursor_pointer()
                .hover(|s| s.bg(t.hover).text_color(t.emphasis))
                .on_click(move |e, w, cx| handler(e, w, cx)),
            None => base.border_color(t.row_rule).text_color(t.text_secondary),
        }
    }
}
