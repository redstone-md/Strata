use super::ClickHandler;
use crate::theme::tokens;
use gpui::{
    App, ClickEvent, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{Icon, IconName, h_flex};
use std::rc::Rc;

/// A checkbox with its label: 1px outlined box, filled light with a dark tick when on.
#[derive(IntoElement)]
pub struct Check {
    id: ElementId,
    label: SharedString,
    checked: bool,
    on_click: ClickHandler,
}

impl Check {
    pub fn new(
        id: impl Into<ElementId>,
        label: impl Into<SharedString>,
        checked: bool,
        on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        Self { id: id.into(), label: label.into(), checked, on_click: Rc::new(on_click) }
    }
}

impl RenderOnce for Check {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let handler = self.on_click;
        let tick = div()
            .size(px(14.))
            .flex()
            .items_center()
            .justify_center()
            .rounded(t.radius)
            .border_1()
            .border_color(if self.checked { t.text } else { t.text_secondary })
            .when(self.checked, |el| el.bg(t.text).child(Icon::new(IconName::Check).size(px(11.)).text_color(t.ink)));
        h_flex()
            .id(self.id)
            .gap(px(8.))
            .cursor_pointer()
            .text_size(t.size_body)
            .text_color(t.text)
            .hover(|s| s.text_color(t.emphasis))
            .child(tick)
            .child(self.label)
            .on_click(move |e, w, cx| handler(e, w, cx))
    }
}
