//! When a disk was in use: the in-use range, a strip of months (bar height = active days),
//! the active periods with what the activity was, typical hours and what was left out.

use crate::theme::{grey, tokens};
use crate::widgets::{Section, quiet};
use gpui::{App, IntoElement, ParentElement, Pixels, RenderOnce, Styled, Window, canvas, div, fill, point, px, size};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{Period, Timestamp, UsageReport};

/// Periods listed under the strip; the rest are counted.
const MAX_PERIODS: usize = 6;
/// Widest bar of one month, in pixels.
const MAX_MONTH_WIDTH: f32 = 24.;
/// Activity kinds named per period.
const KINDS_PER_PERIOD: usize = 3;

pub fn day(t: Timestamp) -> String {
    t.to_string().chars().take(10).collect()
}

/// `2009-03` – `2013-07` style range for compact places (Overview rows).
pub fn short_range(u: &UsageReport) -> Option<String> {
    let month = |t: Timestamp| t.to_string().chars().take(7).collect::<String>();
    Some(format!("{} – {}", month(u.first_day?.0), month(u.last_day?.0)))
}

/// Months of the in-use range as a strip of bars: height by active days, tone by events.
#[derive(IntoElement)]
pub struct ActivityStrip {
    /// `(active days, events)` per month, oldest first.
    months: Vec<(u32, u64)>,
    height: Pixels,
}

impl ActivityStrip {
    pub fn new(u: &UsageReport) -> Self {
        Self { months: u.months.iter().map(|m| (m.active_days, m.events)).collect(), height: px(28.) }
    }

    pub fn height(mut self, height: Pixels) -> Self {
        self.height = height;
        self
    }
}

impl RenderOnce for ActivityStrip {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let months = self.months;
        canvas(
            |_, _, _| (),
            move |bounds, (), window, _| {
                let t = tokens();
                let (w, h) = (bounds.size.width.as_f32(), bounds.size.height.as_f32());
                let base = point(bounds.origin.x, bounds.origin.y + bounds.size.height - px(1.));
                window.paint_quad(fill(gpui::Bounds::new(base, size(bounds.size.width, px(1.))), t.row_rule));
                if months.is_empty() {
                    return;
                }
                // A short range stays a short strip rather than a few wide blocks.
                let step = (w / months.len() as f32).min(MAX_MONTH_WIDTH);
                let gap = if step >= 4.0 { 1.0 } else { 0.0 };
                let most_days = months.iter().map(|m| m.0).max().unwrap_or(1).max(1) as f32;
                let most_events = months.iter().map(|m| m.1).max().unwrap_or(1).max(1) as f32;
                for (i, (days, events)) in months.iter().enumerate().filter(|(_, m)| m.0 > 0) {
                    // At least 3 px so a single active day still shows.
                    let bar = ((*days as f32 / most_days) * (h - 1.0)).max(3.0);
                    let tone = 0.38 + 0.4 * (*events as f32 / most_events).sqrt();
                    let origin = point(bounds.origin.x + px(i as f32 * step), bounds.origin.y + px(h - 1.0 - bar));
                    window.paint_quad(fill(gpui::Bounds::new(origin, size(px((step - gap).max(1.0)), px(bar))), grey(tone)));
                }
            },
        )
        .w_full()
        .h(self.height)
    }
}

pub fn period_line(p: &Period) -> String {
    let kinds: Vec<String> = p.kinds.iter().take(KINDS_PER_PERIOD).map(|k| format!("{} {}", k.kind.label(), k.events)).collect();
    let span = if p.from == p.to { day(p.from.0) } else { format!("{} – {}", day(p.from.0), day(p.to.0)) };
    let days = if p.active_days == 1 { "1 active day".to_string() } else { format!("{} active days", p.active_days) };
    format!("{span}   {days} · {}", kinds.join(", "))
}

/// Typical hours and density: `mostly 18:00–23:00 UTC+03:00 · 2.1 days a month`.
pub fn rhythm(u: &UsageReport) -> String {
    let mut parts = vec![format!("{} active days", u.active_days), format!("{:.1} a month", u.days_per_month)];
    if let Some((a, b)) = u.typical_hours {
        parts.push(format!("mostly {a:02}:00–{b:02}:00 {}", u.clock));
    }
    parts.join(" · ")
}

/// Years at the ends of the strip.
fn strip_ends(u: &UsageReport) -> impl IntoElement {
    let t = tokens();
    let year = |m: Option<&strata_workbench::MonthActivity>| m.map(|m| format!("{:04}-{:02}", m.year, m.month)).unwrap_or_default();
    h_flex().justify_between().text_size(t.size_small).text_color(t.text_secondary).child(year(u.months.first())).child(year(u.months.last()))
}

/// The disk's usage section.
pub fn section(u: &UsageReport) -> impl IntoElement {
    let t = tokens();
    let Some(range) = u.range_label() else {
        return Section::new("Usage").flex_1().min_w(px(300.)).child(quiet().child("No dated user activity yet. The Artifacts step reads it."));
    };
    let last = u.last_day.map(|d| day(d.0)).unwrap_or_default();
    let more = u.periods.len().saturating_sub(MAX_PERIODS);
    let left_out = (!u.outliers.is_empty() || u.out_of_range > 0).then(|| {
        let strays: Vec<String> = u.outliers.iter().take(3).map(|o| day(o.from.0)).collect();
        let mut text = format!("Left out: {} events with impossible dates", u.out_of_range);
        if !strays.is_empty() {
            text.push_str(&format!("; stray activity on {}", strays.join(", ")));
        }
        quiet().text_size(t.size_small).child(text)
    });
    Section::new("Usage")
        .note(range)
        .flex_1()
        .min_w(px(300.))
        .child(
            v_flex()
                .gap(px(4.))
                .child(ActivityStrip::new(u))
                .child(strip_ends(u)),
        )
        .child(
            v_flex()
                .gap(px(2.))
                .text_size(t.size_body)
                .child(h_flex().gap(px(8.)).child(div().text_color(t.text_secondary).child("Last active day")).child(div().text_color(t.emphasis).child(last)))
                .child(div().text_color(t.text).child(rhythm(u))),
        )
        .child(
            v_flex()
                .border_t_1()
                .border_color(t.row_rule)
                .children(u.periods.iter().rev().take(MAX_PERIODS).map(|p| {
                    div().min_h(px(24.)).flex().items_center().border_b_1().border_color(t.row_rule).text_size(t.size_body).text_color(t.text).truncate().child(period_line(p))
                }))
                .children((more > 0).then(|| quiet().pt(px(4.)).child(format!("{more} earlier periods")))),
        )
        .children(left_out)
}
