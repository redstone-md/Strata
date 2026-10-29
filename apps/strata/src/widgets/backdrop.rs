use crate::theme::tokens;

const GLOW_LAYERS: usize = 12;
use gpui::{
    AnyElement, App, BoxShadow, Hsla, IntoElement, ParentElement, Pixels, RenderOnce, Styled, Window,
    div, linear_color_stop, linear_gradient, point, px,
};

/// Window background: deep navy gradient with soft blurred glow blobs behind the content.
#[derive(IntoElement)]
pub struct Backdrop {
    children: Vec<AnyElement>,
}

impl Backdrop {
    pub fn new() -> Self {
        Self { children: Vec::new() }
    }

    /// Soft radial glow centred at `(x, y)`. GPUI has no blur filter, so the falloff is built
    /// from stacked translucent discs, each softened by its own blurred shadow.
    fn glow(x: Pixels, y: Pixels, radius: Pixels, color: Hsla) -> impl IntoElement {
        let layer = color.opacity(color.a / GLOW_LAYERS as f32);
        div().absolute().left(x).top(y).children((0..GLOW_LAYERS).map(move |i| {
            let r = radius * (1.0 - i as f32 / GLOW_LAYERS as f32);
            div()
                .absolute()
                .left(-r)
                .top(-r)
                .size(r * 2.0)
                .rounded_full()
                .bg(layer)
                .shadow(vec![BoxShadow {
                    color: layer,
                    offset: point(px(0.), px(0.)),
                    blur_radius: radius * 0.25,
                    spread_radius: px(0.),
                    inset: false,
                }])
        }))
    }
}

impl ParentElement for Backdrop {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.children.extend(elements);
    }
}

impl RenderOnce for Backdrop {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        div()
            .relative()
            .size_full()
            .overflow_hidden()
            .bg(linear_gradient(160., linear_color_stop(t.bg_top, 0.), linear_color_stop(t.bg_bottom, 1.)))
            .child(Self::glow(px(480.), px(20.), px(380.), t.glow_blue))
            .child(Self::glow(px(1180.), px(620.), px(420.), t.glow_indigo))
            .child(Self::glow(px(60.), px(860.), px(300.), t.glow_blue))
            .child(div().absolute().inset_0().size_full().flex().children(self.children))
    }
}
