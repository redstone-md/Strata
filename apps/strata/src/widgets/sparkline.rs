//! A thin monochrome line of recent values, newest at the right edge, over a 1px baseline.
//! Drawn on a canvas like the sector map; no fill, no axis, no colour.

use crate::theme::tokens;
use gpui::{App, Hsla, IntoElement, PathBuilder, Pixels, RenderOnce, Styled, Window, canvas, fill, point, px, size};

/// Line points for `values` (oldest first) in a `width`×`height` box. The box holds `slots`
/// samples, so a short history starts part-way across; values are scaled to `0..=max`.
pub fn points(values: &[f32], max: f32, width: f32, height: f32, slots: usize) -> Vec<(f32, f32)> {
    let slots = slots.max(2);
    let shown = &values[values.len().saturating_sub(slots)..];
    let step = width / (slots - 1) as f32;
    let first = (slots - shown.len()) as f32 * step;
    let max = if max.is_finite() && max > 0.0 { max } else { 1.0 };
    shown
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let v = if v.is_finite() { v.clamp(0.0, max) } else { 0.0 };
            (first + i as f32 * step, height - v / max * height)
        })
        .collect()
}

/// Scale ceiling: a fixed `max` (percentages), or the data's peak with headroom.
pub fn ceiling(values: &[f32], max: Option<f32>) -> f32 {
    max.unwrap_or_else(|| values.iter().copied().filter(|v| v.is_finite()).fold(0.0, f32::max) * 1.15)
}

#[derive(IntoElement)]
pub struct Sparkline {
    values: Vec<f32>,
    max: Option<f32>,
    slots: usize,
    height: Pixels,
    color: Hsla,
}

impl Sparkline {
    /// `slots`: how many samples the full width holds (300 = five minutes at 1 Hz).
    pub fn new(values: Vec<f32>, slots: usize) -> Self {
        Self { values, max: None, slots, height: px(28.), color: tokens().text }
    }

    /// Fixed top of the scale (100 for percentages).
    pub fn max(mut self, max: f32) -> Self {
        self.max = Some(max);
        self
    }

    pub fn height(mut self, height: Pixels) -> Self {
        self.height = height;
        self
    }
}

impl RenderOnce for Sparkline {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let height = self.height;
        canvas(
            |_, _, _| (),
            move |bounds, (), window, _| {
                let t = tokens();
                let (w, h) = (bounds.size.width.as_f32(), bounds.size.height.as_f32());
                let baseline = point(bounds.origin.x, bounds.origin.y + bounds.size.height - px(1.));
                window.paint_quad(fill(gpui::Bounds::new(baseline, size(bounds.size.width, px(1.))), t.row_rule));
                let max = ceiling(&self.values, self.max);
                // Keep the line clear of the edges so a flat line at the top or bottom shows.
                let pts = points(&self.values, max, w, (h - 2.0).max(1.0), self.slots);
                if pts.len() < 2 {
                    return;
                }
                let mut path = PathBuilder::stroke(px(1.));
                let at = |(x, y): (f32, f32)| point(bounds.origin.x + px(x), bounds.origin.y + px(y + 0.5));
                path.move_to(at(pts[0]));
                for p in &pts[1..] {
                    path.line_to(at(*p));
                }
                if let Ok(path) = path.build() {
                    window.paint_path(path, self.color);
                }
            },
        )
        .w_full()
        .h(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_sample_sits_on_the_right_edge_and_scales_to_height() {
        let p = points(&[0.0, 50.0, 100.0], 100.0, 100.0, 20.0, 5);
        assert_eq!(p, vec![(50.0, 20.0), (75.0, 10.0), (100.0, 0.0)]);
        let full = points(&(0..10).map(|v| v as f32).collect::<Vec<_>>(), 9.0, 90.0, 9.0, 4);
        assert_eq!(full.len(), 4, "only the last `slots` samples");
        assert_eq!(full[0], (0.0, 3.0));
        assert_eq!(points(&[f32::NAN, 500.0], 0.0, 10.0, 10.0, 2), vec![(0.0, 10.0), (10.0, 0.0)]);
        assert!((ceiling(&[2.0, 4.0], None) - 4.6).abs() < 1e-4);
        assert_eq!(ceiling(&[2.0], Some(100.0)), 100.0);
    }
}
