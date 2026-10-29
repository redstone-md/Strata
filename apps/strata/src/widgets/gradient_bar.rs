use crate::theme::tokens;
use gpui::{
    App, Hsla, IntoElement, ParentElement, Pixels, RenderOnce, Styled, Window, div, linear_color_stop,
    linear_gradient, px, relative,
};
use gpui_component::h_flex;

/// Rounded progress bar whose fill is a multi-stop horizontal gradient.
///
/// GPUI gradients have two stops, so N colours are drawn as N-1 adjacent two-stop segments.
#[derive(IntoElement)]
pub struct GradientBar {
    fraction: f32,
    colors: Vec<Hsla>,
    height: Pixels,
}

impl GradientBar {
    pub fn new(fraction: f32, colors: &[Hsla]) -> Self {
        Self { fraction: fraction.clamp(0.0, 1.0), colors: colors.to_vec(), height: px(8.) }
    }

    pub fn rainbow(fraction: f32) -> Self {
        Self::new(fraction, &tokens().rainbow)
    }

    pub fn scan(fraction: f32) -> Self {
        Self::new(fraction, &tokens().scan)
    }

    /// Single solid colour (white "upload" style rows).
    pub fn solid(fraction: f32, color: Hsla) -> Self {
        Self::new(fraction, &[color, color])
    }

    pub fn height(mut self, height: Pixels) -> Self {
        self.height = height;
        self
    }
}

impl RenderOnce for GradientBar {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let segments = self.colors.windows(2).map(|pair| {
            div()
                .flex_1()
                .h_full()
                .bg(linear_gradient(90., linear_color_stop(pair[0], 0.), linear_color_stop(pair[1], 1.)))
        });
        div()
            .w_full()
            .h(self.height)
            .rounded_full()
            .bg(t.track)
            .overflow_hidden()
            .child(h_flex().h_full().w(relative(self.fraction)).rounded_full().overflow_hidden().children(segments))
    }
}
