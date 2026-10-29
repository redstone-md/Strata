//! Events per day as a strip of bars: height is the event count, white bars are days with
//! crypto activity. Days are binned to fit the width; clicking a bar selects its days.

use crate::theme::tokens;
use gpui::{
    App, Bounds, DispatchPhase, IntoElement, MouseButton, MouseDownEvent, MouseMoveEvent, ParentElement, Pixels,
    Styled, Window, canvas, div, fill, point, px, size,
};
use gpui_component::{h_flex, v_flex};
use std::cell::Cell;
use std::rc::Rc;
use strata_workbench::Timestamp;

const BAR_PITCH: f32 = 4.;
const HEIGHT: f32 = 56.;
const DAY_SECS: i64 = 86_400;

/// Inclusive day range `[from, to)` in days since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayRange {
    pub from: i64,
    pub to: i64,
}

impl DayRange {
    pub fn start(self) -> Option<Timestamp> {
        Timestamp::from_unix_secs(self.from * DAY_SECS)
    }

    pub fn end(self) -> Option<Timestamp> {
        Timestamp::from_unix_secs(self.to * DAY_SECS)
    }

    pub fn label(self) -> String {
        let day = |d: i64| Timestamp::from_unix_secs(d * DAY_SECS).map(|t| t.to_string()[..10].to_string()).unwrap_or_default();
        if self.to - self.from <= 1 { day(self.from) } else { format!("{} to {}", day(self.from), day(self.to - 1)) }
    }
}

/// One bar: a run of days and their totals.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Bin {
    range: DayRange,
    total: u64,
    crypto: u64,
}

/// Group `(day, total, crypto)` rows into at most `bins` equal runs of days.
fn bin(days: &[(i64, u64, u64)], bins: usize) -> Vec<Bin> {
    let (Some(first), Some(last)) = (days.first(), days.last()) else { return Vec::new() };
    let span = (last.0 - first.0 + 1).max(1);
    let per = (span as f64 / bins.max(1) as f64).ceil().max(1.0) as i64;
    let count = ((span + per - 1) / per) as usize;
    let mut out: Vec<Bin> = (0..count)
        .map(|i| {
            let from = first.0 + i as i64 * per;
            Bin { range: DayRange { from, to: from + per }, total: 0, crypto: 0 }
        })
        .collect();
    for &(day, total, crypto) in days {
        if let Some(b) = out.get_mut(((day - first.0) / per) as usize) {
            b.total += total;
            b.crypto += crypto;
        }
    }
    out
}

#[derive(Default)]
pub struct DayStrip {
    days: Vec<(i64, u64, u64)>,
    width: Rc<Cell<f32>>,
    hovered: Rc<Cell<Option<usize>>>,
}

impl DayStrip {
    pub fn set_days(&mut self, days: Vec<(Timestamp, u64, u64)>) {
        self.days = days.into_iter().map(|(t, n, c)| (t.unix_secs().div_euclid(DAY_SECS), n, c)).collect();
    }

    pub fn is_empty(&self) -> bool {
        self.days.is_empty()
    }

    fn bins(&self) -> Vec<Bin> {
        let width = if self.width.get() > 0.0 { self.width.get() } else { 1000.0 };
        bin(&self.days, (width / BAR_PITCH) as usize)
    }

    /// The strip and the line under it; `on_pick` gets the clicked bar's days.
    pub fn render(&self, selected: Option<DayRange>, on_pick: impl Fn(DayRange, &mut App) + 'static) -> impl IntoElement {
        let t = tokens();
        let bins = Rc::new(self.bins());
        let max = bins.iter().map(|b| b.total).max().unwrap_or(1).max(1);
        let (width, hovered) = (self.width.clone(), self.hovered.clone());
        let painted = bins.clone();
        let on_pick = Rc::new(on_pick);
        let chart = canvas(
            |_, _, _| (),
            move |bounds: Bounds<Pixels>, (), window: &mut Window, _| {
                if (bounds.size.width.as_f32() - width.get()).abs() >= 1.0 {
                    width.set(bounds.size.width.as_f32());
                    window.refresh();
                }
                for (i, b) in painted.iter().enumerate() {
                    let x = bounds.origin.x + px(i as f32 * BAR_PITCH);
                    if hovered.get() == Some(i) || selected == Some(b.range) {
                        let shade = if selected == Some(b.range) { t.rule } else { t.hover };
                        window.paint_quad(fill(Bounds::new(point(x, bounds.origin.y), size(px(BAR_PITCH - 1.), bounds.size.height)), shade));
                    }
                    if b.total == 0 {
                        continue;
                    }
                    let h = (HEIGHT * (b.total as f32 / max as f32).sqrt()).max(1.0);
                    let color = if b.crypto > 0 { t.emphasis } else { t.cell_scanned };
                    let top = bounds.origin.y + bounds.size.height - px(h);
                    window.paint_quad(fill(Bounds::new(point(x, top), size(px(BAR_PITCH - 1.), px(h))), color));
                }
                let n = painted.len();
                let index = move |p: gpui::Point<Pixels>| {
                    bounds.contains(&p).then(|| ((p.x - bounds.origin.x).as_f32() / BAR_PITCH) as usize).filter(|i| *i < n)
                };
                let hover = hovered.clone();
                window.on_mouse_event(move |e: &MouseMoveEvent, phase, window, _| {
                    if phase == DispatchPhase::Bubble && hover.get() != index(e.position) {
                        hover.set(index(e.position));
                        window.refresh();
                    }
                });
                let (pick, picked) = (on_pick.clone(), painted.clone());
                window.on_mouse_event(move |e: &MouseDownEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && e.button == MouseButton::Left
                        && let Some(i) = index(e.position)
                    {
                        pick(picked[i].range, cx);
                    }
                });
            },
        )
        .w_full()
        .h(px(HEIGHT));
        let status = match self.hovered.get().and_then(|i| bins.get(i)) {
            Some(b) => format!("{}: {} events, {} with crypto", b.range.label(), b.total, b.crypto),
            None => "Bars show events per day; white bars have crypto activity. Click a bar to see its days.".into(),
        };
        let edge = |b: Option<&Bin>| b.map(|b| DayRange { from: b.range.from, to: b.range.from + 1 }.label()).unwrap_or_default();
        v_flex()
            .gap(px(6.))
            .child(chart)
            .child(
                h_flex()
                    .justify_between()
                    .gap_4()
                    .text_size(t.size_small)
                    .text_color(t.text_secondary)
                    .child(edge(bins.first()))
                    .child(div().text_color(t.text).child(status))
                    .child(edge(bins.last())),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bins_days_into_runs() {
        let days = [(100, 5, 0), (101, 1, 1), (110, 2, 0)];
        let one = bin(&days, 100);
        assert_eq!(one.len(), 11);
        assert_eq!((one[1].total, one[1].crypto), (1, 1));
        let few = bin(&days, 2);
        assert_eq!(few.len(), 2);
        assert_eq!(few[0].total, 6);
        assert_eq!(few[1].range, DayRange { from: 106, to: 112 });
        assert!(bin(&[], 10).is_empty());
    }
}
