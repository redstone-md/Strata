use crate::theme::tokens;
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

    fn blob(left: Pixels, top: Pixels, size: Pixels, color: Hsla) -> impl IntoElement {
        div()
            .absolute()
            .left(left)
            .top(top)
            .size(size)
            .rounded_full()
            .shadow(vec![BoxShadow {
                color,
                offset: point(px(0.), px(0.)),
                blur_radius: size,
                spread_radius: size * 0.1,
                inset: false,
            }])
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
            .child(Self::blob(px(260.), px(-180.), px(420.), t.glow_blue))
            .child(Self::blob(px(980.), px(380.), px(380.), t.glow_indigo))
            .child(Self::blob(px(-120.), px(620.), px(320.), t.glow_blue.opacity(0.6)))
            .child(div().absolute().inset_0().size_full().flex().children(self.children))
    }
}
