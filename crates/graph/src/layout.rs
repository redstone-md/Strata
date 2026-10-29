//! Places a view's nodes for drawing: a force-directed layout (Fruchterman–Reingold) started
//! from rings by depth, with a fixed number of steps and no randomness, so the same view always
//! lands the same way. Units are pixels at zoom 1; the centre of an ego view stays at the origin.

use crate::view::GraphView;
use std::collections::BTreeMap;

/// Ideal distance between linked nodes.
const SPACING: f32 = 110.0;
const STEPS: usize = 300;
/// Pull towards the origin that keeps separate components on screen.
const GRAVITY: f32 = 0.008;
const GOLDEN_ANGLE: f32 = 2.399_963;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Layout {
    points: Vec<(f32, f32)>,
}

impl Layout {
    pub fn compute(view: &GraphView) -> Self {
        let n = view.nodes.len();
        let mut points = Self::start(view);
        if n < 2 {
            return Self { points };
        }
        let pinned = view.centre;
        let k2 = SPACING * SPACING;
        let mut heat = SPACING * 1.5;
        let cool = (2.0f32 / heat).powf(1.0 / STEPS as f32);
        let mut push = vec![(0.0f32, 0.0f32); n];
        for _ in 0..STEPS {
            push.iter_mut().for_each(|p| *p = (0.0, 0.0));
            for i in 0..n {
                for j in i + 1..n {
                    let (mut dx, mut dy) = (points[i].0 - points[j].0, points[i].1 - points[j].1);
                    let mut d2 = dx * dx + dy * dy;
                    if d2 < 1e-4 {
                        // Same spot: part them along a direction fixed by the pair.
                        let a = (i * 31 + j * 17) as f32;
                        (dx, dy, d2) = (a.cos() * 0.01, a.sin() * 0.01, 1e-4);
                    }
                    let f = k2 / d2;
                    push[i].0 += dx * f;
                    push[i].1 += dy * f;
                    push[j].0 -= dx * f;
                    push[j].1 -= dy * f;
                }
            }
            for e in &view.edges {
                let (a, b) = (e.from, e.to);
                let (dx, dy) = (points[a].0 - points[b].0, points[a].1 - points[b].1);
                let d = (dx * dx + dy * dy).sqrt().max(0.01);
                let f = d / SPACING * e.kind.strength();
                push[a].0 -= dx * f;
                push[a].1 -= dy * f;
                push[b].0 += dx * f;
                push[b].1 += dy * f;
            }
            for i in 0..n {
                if Some(i) == pinned {
                    continue;
                }
                let (gx, gy) = (push[i].0 - points[i].0 * GRAVITY * SPACING, push[i].1 - points[i].1 * GRAVITY * SPACING);
                let len = (gx * gx + gy * gy).sqrt();
                if len > 0.0 {
                    let step = len.min(heat) / len;
                    points[i].0 += gx * step;
                    points[i].1 += gy * step;
                }
            }
            heat *= cool;
        }
        Self { points }
    }

    /// Rings by depth, each filled along a golden-angle spiral in view order (best first).
    fn start(view: &GraphView) -> Vec<(f32, f32)> {
        let mut rings: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (i, v) in view.nodes.iter().enumerate() {
            rings.entry(if Some(i) == view.centre { 0 } else { v.depth.max(u32::from(view.centre.is_some())) }).or_default().push(i);
        }
        let mut points = vec![(0.0, 0.0); view.nodes.len()];
        for (depth, members) in rings {
            let base = depth as f32 * SPACING * 1.4;
            for (k, i) in members.into_iter().enumerate() {
                if Some(i) == view.centre {
                    continue;
                }
                let r = base + SPACING * 0.6 * (k as f32).sqrt();
                let a = k as f32 * GOLDEN_ANGLE + depth as f32;
                points[i] = (r * a.cos(), r * a.sin());
            }
        }
        points
    }

    pub fn point(&self, i: usize) -> Option<(f32, f32)> {
        self.points.get(i).copied()
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// `(min x, min y, max x, max y)` of all points.
    pub fn bounds(&self) -> Option<(f32, f32, f32, f32)> {
        let first = self.points.first()?;
        Some(self.points.iter().fold((first.0, first.1, first.0, first.1), |b, p| (b.0.min(p.0), b.1.min(p.1), b.2.max(p.0), b.3.max(p.1))))
    }
}
