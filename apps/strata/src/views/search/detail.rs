//! Side panel for one match: where it is, then 4 KiB either side of it as hex or text.

use super::results::location_badge;
use crate::format;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, HexMode, HexView, TextButton, mode_choice, mono, quiet, rule};
use gpui::{
    App, ClipboardItem, IntoElement, ParentElement, RenderOnce, Styled, UniformListScrollHandle, Window, div, px,
};
use gpui_component::{h_flex, v_flex};
use std::sync::Arc;
use std::rc::Rc;
use strata_workbench::{Encoding, SearchResultRow};

pub const WIDTH: f32 = 620.;
/// Bytes shown on each side of the match.
pub const AROUND: u64 = 4096;

#[derive(IntoElement)]
pub struct MatchDetail {
    pub row: SearchResultRow,
    pub disk: String,
    pub bytes: Arc<Vec<u8>>,
    pub base: u64,
    pub mode: HexMode,
    pub scroll: UniformListScrollHandle,
    pub on_close: ClickHandler,
    pub on_mode: Rc<dyn Fn(HexMode, &mut Window, &mut App)>,
}

impl MatchDetail {
    /// Text view in the match's own encoding.
    pub fn text_mode(row: &SearchResultRow) -> HexMode {
        HexMode::Text(Encoding::ALL.into_iter().find(|e| e.name() == row.encoding).unwrap_or(Encoding::Utf8))
    }

    fn fact(label: &str, value: String) -> impl IntoElement {
        let t = tokens();
        h_flex()
            .gap(px(12.))
            .text_size(t.size_body)
            .child(div().w(px(96.)).flex_shrink_0().text_color(t.text_secondary).child(label.to_string()))
            .child(mono().min_w_0().text_color(t.text).truncate().child(value))
    }
}

impl RenderOnce for MatchDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let r = &self.row;
        let at = (r.offset - self.base) as usize;
        let mark = at..at + r.len as usize;
        let offset = format::hex_offset(r.offset);
        let (close, on_mode) = (self.on_close.clone(), self.on_mode.clone());
        let place = r.file_path.clone().unwrap_or_else(|| "free space".into());
        let file_offset = r.file_offset.map(format::hex_offset).unwrap_or_else(|| "—".into());
        let volume = r.volume.map_or_else(|| "outside volumes".into(), |v| format!("volume {v}"));
        let hex = HexView::new("match-hex", self.bytes.clone(), self.base).mark(mark).mode(self.mode).scroll(&self.scroll);
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex()
                    .p(px(20.))
                    .pb(px(12.))
                    .gap(px(10.))
                    .child(
                        h_flex()
                            .justify_between()
                            .items_start()
                            .gap(px(12.))
                            .child(
                                v_flex()
                                    .gap(px(6.))
                                    .min_w_0()
                                    .child(h_flex().child(location_badge(&r.location)))
                                    .child(mono().text_size(t.size_heading).text_color(t.emphasis).whitespace_normal().child(place)),
                            )
                            .child(TextButton::new("match-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                    )
                    .child(Self::fact("Disk", self.disk.clone()))
                    .child(Self::fact("Disk offset", offset.clone()))
                    .child(Self::fact("In file at", file_offset))
                    .child(Self::fact("Volume", volume))
                    .child(Self::fact("Encoding", r.encoding.clone()))
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .pt(px(4.))
                            .child(TextButton::new("match-copy", "Copy offset").on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(offset.clone()))))
                            .child(div().w(px(12.)))
                            .child(mode_choice("match-mode", self.mode, move |m, w, cx| on_mode(m, w, cx))),
                    ),
            )
            .child(rule())
            .child(
                v_flex()
                    .flex_1()
                    .min_h_0()
                    .px(px(20.))
                    .py(px(10.))
                    .gap(px(6.))
                    .child(quiet().text_size(t.size_small).child(format!("{} either side of the match, as it is on the disk now", format::bytes(AROUND))))
                    .child(div().flex_1().min_h_0().child(hex)),
            )
    }
}
