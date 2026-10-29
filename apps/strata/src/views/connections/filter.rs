//! The kind filter, which doubles as the map's legend: one chip per kind with its shape, the
//! number shown, and a click to hide or show that kind.

use super::look;
use super::paint;
use crate::theme::tokens;
use gpui::{App, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, StatefulInteractiveElement as _, Styled, Window, canvas, div, px};
use gpui_component::h_flex;
use std::rc::Rc;
use strata_workbench::NodeKind;

type ToggleHandler = Rc<dyn Fn(NodeKind, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct KindFilter {
    hidden: Vec<NodeKind>,
    /// Nodes per kind in the view on screen.
    shown: Vec<(NodeKind, usize)>,
    on_toggle: ToggleHandler,
}

impl KindFilter {
    pub fn new(hidden: Vec<NodeKind>, shown: Vec<(NodeKind, usize)>, on_toggle: impl Fn(NodeKind, &mut Window, &mut App) + 'static) -> Self {
        Self { hidden, shown, on_toggle: Rc::new(on_toggle) }
    }
}

/// The kind's shape at legend size.
fn swatch(kind: NodeKind) -> impl IntoElement {
    canvas(|_, _, _| (), move |bounds, (), window, _| paint::node(window, bounds.center(), &look::legend(kind), 1.0, 1.0)).size(px(16.)).flex_shrink_0()
}

impl RenderOnce for KindFilter {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        h_flex().flex_wrap().gap(px(4.)).children(NodeKind::ALL.into_iter().map(|kind| {
            let on = !self.hidden.contains(&kind);
            let count = self.shown.iter().find(|(k, _)| *k == kind).map_or(0, |(_, n)| *n);
            let toggle = self.on_toggle.clone();
            h_flex()
                .id(ElementId::Name(format!("kind-{}", kind.name()).into()))
                .h(px(26.))
                .px(px(8.))
                .gap(px(6.))
                .items_center()
                .rounded(t.radius)
                .border_1()
                .border_color(if on { t.rule } else { gpui::transparent_black() })
                .text_size(t.size_small)
                .text_color(if on { t.text } else { t.text_secondary })
                .opacity(if on { 1.0 } else { 0.55 })
                .cursor_pointer()
                .hover(|s| s.text_color(t.emphasis))
                .child(swatch(kind))
                .child(kind.plural())
                .children((on && count > 0).then(|| div().text_color(t.text_secondary).child(count.to_string())))
                .on_click(move |_, w, cx| toggle(kind, w, cx))
        }))
    }
}
