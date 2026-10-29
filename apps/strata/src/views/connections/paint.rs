//! Drawing primitives of the map: the camera that maps layout units to the screen, node shapes,
//! links and labels. Pure geometry plus `Window` paint calls, no view state.

use super::look::{Look, Shape};
use crate::theme::tokens;
use gpui::{App, BorderStyle, Bounds, Hsla, PathBuilder, Pixels, Point, SharedString, TextAlign, TextRun, Window, point, px, quad, size};

/// Zoom range the wheel can reach.
const MIN_ZOOM: f32 = 0.2;
/// A fit never zooms out further than this; the rest is a pan or a wheel turn away.
const MIN_FIT: f32 = 0.6;
const MAX_ZOOM: f32 = 3.0;
/// Room kept around the drawing when fitting it to the canvas.
const FIT_MARGIN: f32 = 120.0;

/// Pan (pixels from the canvas centre) and zoom of the map.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Camera {
    pub pan: (f32, f32),
    pub zoom: f32,
}

impl Default for Camera {
    fn default() -> Self {
        Self { pan: (0.0, 0.0), zoom: 1.0 }
    }
}

impl Camera {
    /// Show `(min x, min y, max x, max y)` whole inside a canvas of `w` × `h`, never enlarged
    /// past zoom 1.2.
    pub fn fit(bounds: (f32, f32, f32, f32), w: f32, h: f32) -> Self {
        let (bw, bh) = ((bounds.2 - bounds.0).max(1.0), (bounds.3 - bounds.1).max(1.0));
        let zoom = ((w - FIT_MARGIN) / bw).min((h - FIT_MARGIN) / bh).clamp(MIN_FIT, 1.2);
        let centre = ((bounds.0 + bounds.2) / 2.0, (bounds.1 + bounds.3) / 2.0);
        Self { pan: (-centre.0 * zoom, -centre.1 * zoom), zoom }
    }

    pub fn screen(&self, canvas: Bounds<Pixels>, p: (f32, f32)) -> Point<Pixels> {
        let c = canvas.center();
        point(px(c.x.as_f32() + self.pan.0 + p.0 * self.zoom), px(c.y.as_f32() + self.pan.1 + p.1 * self.zoom))
    }

    /// Zoom by `factor` keeping the point under `at` (relative to the canvas centre) in place.
    pub fn zoom_at(&mut self, factor: f32, at: (f32, f32)) {
        let zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let k = zoom / self.zoom;
        self.pan = (at.0 - (at.0 - self.pan.0) * k, at.1 - (at.1 - self.pan.1) * k);
        self.zoom = zoom;
    }

    /// How much marks grow with zoom: less than the layout, so a zoomed-out map stays legible.
    pub fn mark_scale(&self) -> f32 {
        self.zoom.sqrt().clamp(0.7, 1.5)
    }
}

/// Corners of a polygon shape around `c` with half-size `r`.
fn polygon(shape: Shape, c: (f32, f32), r: f32) -> Vec<(f32, f32)> {
    let (x, y) = c;
    match shape {
        Shape::Diamond => vec![(x, y - r * 1.25), (x + r * 1.25, y), (x, y + r * 1.25), (x - r * 1.25, y)],
        Shape::Triangle => vec![(x, y - r * 1.2), (x + r * 1.1, y + r * 0.8), (x - r * 1.1, y + r * 0.8)],
        Shape::Hexagon => (0..6).map(|i| (i as f32 * std::f32::consts::FRAC_PI_3).sin_cos()).map(|(s, c)| (x + r * c, y + r * s)).collect(),
        _ => Vec::new(),
    }
}

fn path(points: &[(f32, f32)], builder: PathBuilder) -> Option<gpui::Path<Pixels>> {
    let mut b = builder;
    let (first, rest) = points.split_first()?;
    b.move_to(point(px(first.0), px(first.1)));
    for p in rest {
        b.line_to(point(px(p.0), px(p.1)));
    }
    b.close();
    b.build().ok()
}

/// Paint one node centred at `c`. `alpha` dims nodes outside the hovered neighbourhood.
pub fn node(window: &mut Window, c: Point<Pixels>, look: &Look, scale: f32, alpha: f32) {
    let t = tokens();
    let r = look.radius * scale;
    let (x, y) = (c.x.as_f32(), c.y.as_f32());
    let fill = look.fill.unwrap_or(t.ground).opacity(if look.fill.is_some() { alpha } else { 1.0 });
    let stroke = look.stroke.opacity(alpha);
    let style = if look.dashed { BorderStyle::Dashed } else { BorderStyle::Solid };
    let rect = |w: f32, h: f32| Bounds::new(point(px(x - w), px(y - h)), size(px(w * 2.0), px(h * 2.0)));
    let boxed = |window: &mut Window, b: Bounds<Pixels>, corner: f32| window.paint_quad(quad(b, px(corner), fill, px(1.), stroke, style));
    match look.shape {
        Shape::Circle => boxed(window, rect(r, r), r),
        Shape::RoundSquare => boxed(window, rect(r * 0.9, r * 0.9), 3.0),
        Shape::Square => boxed(window, rect(r * 0.85, r * 0.85), 0.0),
        Shape::Page => boxed(window, rect(r * 0.75, r), 1.0),
        Shape::Slab => boxed(window, rect(r * 1.5, r * 0.7), 2.0),
        Shape::Envelope => {
            let b = rect(r, r * 0.7);
            boxed(window, b, 1.0);
            let (l, top, w, h) = (b.origin.x.as_f32(), b.origin.y.as_f32(), b.size.width.as_f32(), b.size.height.as_f32());
            let mut v = PathBuilder::stroke(px(1.));
            v.move_to(point(px(l), px(top)));
            v.line_to(point(px(l + w / 2.0), px(top + h * 0.6)));
            v.line_to(point(px(l + w), px(top)));
            if let Ok(p) = v.build() {
                window.paint_path(p, stroke);
            }
        }
        shape => {
            let corners = polygon(shape, (x, y), r);
            if let Some(p) = path(&corners, PathBuilder::fill()) {
                window.paint_path(p, fill);
            }
            if let Some(p) = path(&corners, PathBuilder::stroke(px(1.))) {
                window.paint_path(p, stroke);
            }
        }
    }
    if look.ring {
        let g = r + 3.5;
        let ring = stroke.opacity(0.7);
        match polygon(look.shape, (x, y), g) {
            corners if corners.is_empty() => {
                let corner = if look.shape == Shape::Circle { g } else { 2.0 };
                window.paint_quad(quad(rect(g, g), px(corner), gpui::transparent_black(), px(1.), ring, BorderStyle::Solid));
            }
            corners => {
                if let Some(p) = path(&corners, PathBuilder::stroke(px(1.))) {
                    window.paint_path(p, ring);
                }
            }
        }
    }
}

/// A straight link between two node centres.
pub fn link(window: &mut Window, a: Point<Pixels>, b: Point<Pixels>, width: f32, color: Hsla, dashed: bool) {
    let mut p = PathBuilder::stroke(px(width));
    if dashed {
        p = p.dash_array(&[px(3.), px(3.)]);
    }
    p.move_to(a);
    p.line_to(b);
    if let Ok(path) = p.build() {
        window.paint_path(path, color);
    }
}

/// One line of text with its left edge at `at.x`, vertically centred on `at.y`, over a patch
/// of ground so links behind it do not cross the letters. Skipped (returns false) when it would
/// overlap a label in `taken`, so callers paint the most important labels first.
#[allow(clippy::too_many_arguments)]
pub fn label(window: &mut Window, cx: &mut App, taken: &mut Vec<Bounds<Pixels>>, text: SharedString, at: Point<Pixels>, font: &'static str, size_px: f32, color: Hsla) -> bool {
    let t = tokens();
    let run = TextRun { len: text.len(), font: gpui::font(font), color, background_color: None, underline: None, strikethrough: None };
    let line = window.text_system().shape_line(text, px(size_px), &[run], None);
    let height = size_px + 4.0;
    let origin = point(at.x, at.y - px(height / 2.0));
    let patch = Bounds::new(point(origin.x - px(2.), origin.y), size(line.width + px(4.), px(height)));
    if taken.iter().any(|b| b.intersects(&patch)) {
        return false;
    }
    taken.push(patch);
    window.paint_quad(gpui::fill(patch, t.ground.opacity(0.82)));
    let _ = line.paint(origin, px(height), TextAlign::Left, None, window, cx);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fits_and_zooms_around_the_cursor() {
        let cam = Camera::fit((-100.0, -50.0, 100.0, 50.0), 1000.0, 600.0);
        assert!((cam.zoom - 1.2).abs() < 1e-6 && cam.pan == (0.0, 0.0));
        let wide = Camera::fit((0.0, 0.0, 4000.0, 100.0), 1000.0, 600.0);
        assert!((wide.zoom - MIN_FIT).abs() < 1e-6 && wide.pan.0 < 0.0);
        let mut c = Camera::default();
        let world = |c: &Camera, at: (f32, f32)| ((at.0 - c.pan.0) / c.zoom, (at.1 - c.pan.1) / c.zoom);
        let before = world(&c, (50.0, 20.0));
        c.zoom_at(1.5, (50.0, 20.0));
        let after = world(&c, (50.0, 20.0));
        assert!((before.0 - after.0).abs() < 1e-3 && (before.1 - after.1).abs() < 1e-3);
        c.zoom_at(100.0, (0.0, 0.0));
        assert_eq!(c.zoom, MAX_ZOOM);
    }

    #[test]
    fn polygons_have_their_corners() {
        assert_eq!(polygon(Shape::Hexagon, (0.0, 0.0), 5.0).len(), 6);
        assert_eq!(polygon(Shape::Diamond, (0.0, 0.0), 5.0).len(), 4);
        assert!(polygon(Shape::Circle, (0.0, 0.0), 5.0).is_empty());
    }
}
