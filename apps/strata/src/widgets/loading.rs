//! Motion for work in progress: a 2 px line with a travelling segment (same weight as the
//! command bar's progress line) and the logo grid swept like a scan. Both are indeterminate:
//! they say "working", never a fake percentage.

use crate::theme::{grey, tokens};
use gpui::{Animation, AnimationExt as _, ElementId, IntoElement, ParentElement as _, Styled as _, div, ease_in_out, px, relative};
use gpui_component::{h_flex, v_flex};
use std::time::Duration;

/// Logo grid tones per row, dark to light (assets/logo.svg).
const ROW_TONES: [f32; 5] = [0.227, 0.290, 0.353, 0.431, 0.549];
/// The white "finding" cell of the logo.
const FINDING: (usize, usize) = (1, 3);
/// Cells behind the sweep head that still glow.
const TRAIL: f32 = 5.0;

/// Indeterminate 2 px line: a segment slides across a hairline.
pub fn loading_line(id: impl Into<ElementId>) -> impl IntoElement {
    let t = tokens();
    div().w_full().h(px(2.)).flex_shrink_0().relative().overflow_hidden().child(div().absolute().top(px(1.)).w_full().h(px(1.)).bg(t.rule)).child(
        div().absolute().top_0().h_full().w(relative(0.28)).bg(t.emphasis).with_animation(
            id,
            Animation::new(Duration::from_millis(1400)).repeat().with_easing(ease_in_out),
            |seg, f| seg.left(relative(-0.28 + f * 1.28)),
        ),
    )
}

/// [`loading_line`] laid over the top edge of its (relatively positioned) parent, so showing
/// it never moves the layout.
pub fn loading_edge(id: impl Into<ElementId>) -> impl IntoElement {
    div().absolute().top_0().left_0().right_0().child(loading_line(id))
}

/// The logo grid with a scan sweeping through its cells in reading order.
pub fn scan_grid(id: impl Into<ElementId>, cell: f32) -> impl IntoElement {
    let gap = (cell * 0.22).round().max(2.);
    v_flex().gap(px(gap)).with_animation(id, Animation::new(Duration::from_millis(1800)).repeat(), move |grid, f| {
        let head = f * (25.0 + TRAIL);
        grid.children((0..5).map(|r| {
            h_flex().gap(px(gap)).children((0..5).map(move |c| {
                let behind = head - (r * 5 + c) as f32;
                let glow = if (0.0..TRAIL).contains(&behind) { 1.0 - behind / TRAIL } else { 0.0 };
                let tone = if (r, c) == FINDING { 1.0 } else { ROW_TONES[r] + (0.92 - ROW_TONES[r]) * glow * 0.75 };
                div().size(px(cell)).bg(grey(tone))
            }))
        }))
    })
}
