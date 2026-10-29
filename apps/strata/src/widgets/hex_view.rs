//! Bytes as an offset / hex / text dump, or as decoded text lines, with one marked range
//! shown inverted (the monochrome highlight). Rows are virtualised, so 64 KiB is cheap.

use crate::theme::tokens;
use gpui::{
    App, ElementId, IntoElement, ParentElement, RenderOnce, ScrollStrategy, SharedString, Styled, UniformListScrollHandle, Window,
    div, px, uniform_list,
};
use gpui_component::h_flex;
use std::ops::Range;
use std::sync::Arc;
use strata_workbench::Encoding;

const HEX_ROW: usize = 16;
const TEXT_ROW: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HexMode {
    Hex,
    /// Decoded text in the given encoding.
    Text(Encoding),
}

/// The ways a byte view can be shown, in picker order.
pub const VIEW_MODES: [(&str, HexMode); 5] = [
    ("Hex", HexMode::Hex),
    ("UTF-8", HexMode::Text(Encoding::Utf8)),
    ("UTF-16LE", HexMode::Text(Encoding::Utf16Le)),
    ("CP1251", HexMode::Text(Encoding::Cp1251)),
    ("CP866", HexMode::Text(Encoding::Cp866)),
];

/// Picker over [`VIEW_MODES`].
pub fn mode_choice(id: &'static str, mode: HexMode, on_select: impl Fn(HexMode, &mut Window, &mut App) + 'static) -> super::Choice {
    let labels = VIEW_MODES.iter().map(|m| SharedString::from(m.0)).collect();
    let selected = VIEW_MODES.iter().position(|m| m.1 == mode).unwrap_or(0);
    super::Choice::new(id, labels, selected, move |i, w, cx| on_select(VIEW_MODES.get(i).map_or(HexMode::Hex, |m| m.1), w, cx))
}

/// Offset column text: 8 hex digits while they suffice.
fn offset(at: u64) -> String {
    if at <= u64::from(u32::MAX) { format!("{at:08X}") } else { format!("{at:010X}") }
}

#[derive(IntoElement)]
pub struct HexView {
    id: ElementId,
    bytes: Arc<Vec<u8>>,
    /// Offset of `bytes[0]` (shown in the offset column).
    base: u64,
    /// Marked byte range, relative to `bytes`.
    mark: Option<Range<usize>>,
    mode: HexMode,
    scroll: Option<UniformListScrollHandle>,
}

impl HexView {
    pub fn new(id: impl Into<ElementId>, bytes: Arc<Vec<u8>>, base: u64) -> Self {
        Self { id: id.into(), bytes, base, mark: None, mode: HexMode::Hex, scroll: None }
    }

    pub fn mark(mut self, mark: Range<usize>) -> Self {
        self.mark = Some(mark);
        self
    }

    pub fn mode(mut self, mode: HexMode) -> Self {
        self.mode = mode;
        self
    }

    /// Track scrolling with `handle` (see [`HexView::reveal`]).
    pub fn scroll(mut self, handle: &UniformListScrollHandle) -> Self {
        self.scroll = Some(handle.clone());
        self
    }

    /// Scroll `handle` so the row holding byte `at` is in the middle.
    pub fn reveal(handle: &UniformListScrollHandle, at: usize, mode: HexMode) {
        let row = at / if mode == HexMode::Hex { HEX_ROW } else { TEXT_ROW };
        handle.scroll_to_item(row, ScrollStrategy::Center);
    }

    fn row_len(&self) -> usize {
        match self.mode {
            HexMode::Hex => HEX_ROW,
            HexMode::Text(_) => TEXT_ROW,
        }
    }
}

/// `(before, marked, after)` index ranges of one row.
fn split(row: Range<usize>, mark: &Option<Range<usize>>) -> [Range<usize>; 3] {
    let Some(m) = mark else { return [row.clone(), row.end..row.end, row.end..row.end] };
    let from = m.start.clamp(row.start, row.end);
    let to = m.end.clamp(from, row.end);
    [row.start..from, from..to, to..row.end]
}

fn printable(b: u8) -> char {
    if b.is_ascii_graphic() || b == b' ' { b as char } else { '·' }
}

fn segments(parts: [String; 3]) -> impl IntoElement {
    let t = tokens();
    let [a, m, b] = parts;
    h_flex()
        .child(div().text_color(t.text).child(a))
        .child(div().bg(t.text).text_color(t.ink).child(m))
        .child(div().text_color(t.text).child(b))
}

fn hex_row(bytes: &[u8], base: u64, start: usize, mark: &Option<Range<usize>>) -> impl IntoElement {
    let t = tokens();
    let end = (start + HEX_ROW).min(bytes.len());
    let parts = split(start..end, mark);
    let hex = |r: &Range<usize>| bytes[r.clone()].iter().map(|b| format!("{b:02X} ")).collect::<String>();
    let text = |r: &Range<usize>| bytes[r.clone()].iter().map(|b| printable(*b)).collect::<String>();
    let pad = " ".repeat((HEX_ROW - (end - start)) * 3);
    h_flex()
        .h(px(20.))
        .gap(px(12.))
        .child(div().w(px(76.)).flex_shrink_0().text_color(t.text_secondary).child(offset(base + start as u64)))
        .child(h_flex().child(segments(parts.clone().map(|r| hex(&r)))).child(pad))
        .child(segments(parts.map(|r| text(&r))))
}

fn text_row(bytes: &[u8], base: u64, start: usize, mark: &Option<Range<usize>>, encoding: Encoding) -> impl IntoElement {
    let t = tokens();
    let end = (start + TEXT_ROW).min(bytes.len());
    let parts = split(start..end, mark).map(|r| encoding.decode(&bytes[r]));
    h_flex()
        .h(px(20.))
        .gap(px(16.))
        .child(div().w(px(76.)).flex_shrink_0().text_color(t.text_secondary).child(offset(base + start as u64)))
        .child(segments(parts))
}

impl RenderOnce for HexView {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let row_len = self.row_len();
        let rows = self.bytes.len().div_ceil(row_len);
        let (bytes, base, mark, mode) = (self.bytes.clone(), self.base, self.mark.clone(), self.mode);
        let list = uniform_list(self.id, rows, move |range, _, _| {
            range
                .map(|r| match mode {
                    HexMode::Hex => hex_row(&bytes, base, r * HEX_ROW, &mark).into_any_element(),
                    HexMode::Text(e) => text_row(&bytes, base, r * TEXT_ROW, &mark, e).into_any_element(),
                })
                .collect()
        });
        let list = match &self.scroll {
            Some(h) => list.track_scroll(h),
            None => list,
        };
        div()
            .size_full()
            .font_family(t.font_data)
            .text_size(t.size_small)
            .child(if self.bytes.is_empty() {
                div().text_color(t.text_secondary).child(SharedString::from("No bytes to show.")).into_any_element()
            } else {
                list.size_full().into_any_element()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn splits_rows_around_the_mark() {
        assert_eq!(split(16..32, &Some(20..40)), [16..20, 20..32, 32..32]);
        assert_eq!(split(0..16, &Some(20..40)), [0..16, 16..16, 16..16]);
        assert_eq!(split(0..16, &None), [0..16, 16..16, 16..16]);
    }
}
