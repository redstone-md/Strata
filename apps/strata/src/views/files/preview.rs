//! Bottom pane of Files: facts about the selected file beside its first 64 KiB as hex or text.

use crate::format;
use crate::theme::tokens;
use crate::views::search::state_badge;
use crate::widgets::{Badge, ClickHandler, HexMode, HexView, TextButton, mode_choice, mono, quiet};
use gpui::{App, IntoElement, ParentElement, RenderOnce, Styled, UniformListScrollHandle, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::sync::Arc;
use std::rc::Rc;
use strata_workbench::FileView;

pub const HEIGHT: f32 = 340.;
const FACTS_WIDTH: f32 = 340.;
/// Bytes of a file shown in the preview.
pub const PREVIEW_BYTES: usize = 64 * 1024;

#[derive(IntoElement)]
pub struct FilePreview {
    pub file: FileView,
    pub bytes: Arc<Vec<u8>>,
    pub mode: HexMode,
    pub scroll: UniformListScrollHandle,
    pub on_close: ClickHandler,
    pub on_mode: Rc<dyn Fn(HexMode, &mut Window, &mut App)>,
}

impl RenderOnce for FilePreview {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let f = &self.file;
        let (close, on_mode) = (self.on_close.clone(), self.on_mode.clone());
        let fact = |label: &str, value: String| {
            h_flex()
                .gap(px(12.))
                .text_size(t.size_body)
                .child(div().w(px(80.)).flex_shrink_0().text_color(t.text_secondary).child(label.to_string()))
                .child(mono().min_w_0().text_color(t.text).truncate().child(value))
        };
        let time = |ts: Option<strata_workbench::Timestamp>| ts.map(|t| t.to_string()).unwrap_or_else(|| "—".into());
        let shown = if (f.size as usize) > PREVIEW_BYTES {
            format!("First {} of {}", format::bytes(PREVIEW_BYTES as u64), format::bytes(f.size))
        } else {
            format!("{} in full", format::bytes(f.size))
        };
        let note = if f.damaged || f.state != strata_workbench::FileEntryState::Allocated {
            " as the clusters read now; parts of a deleted file may belong to newer data"
        } else {
            ""
        };
        h_flex()
            .w_full()
            .h(px(HEIGHT))
            .flex_shrink_0()
            .items_start()
            .border_t_1()
            .border_color(t.rule)
            .child(
                v_flex()
                    .w(px(FACTS_WIDTH))
                    .flex_shrink_0()
                    .h_full()
                    .pt(px(14.))
                    .pr(px(20.))
                    .gap(px(8.))
                    .child(
                        h_flex()
                            .justify_between()
                            .items_start()
                            .gap(px(12.))
                            .child(
                                v_flex()
                                    .gap(px(6.))
                                    .min_w_0()
                                    .child(
                                        h_flex()
                                            .gap(px(6.))
                                            .children(state_badge(super::delegate::state_word(f.state)))
                                            .children(f.in_deleted_partition.then(|| Badge::outline("deleted partition")))
                                            .children(f.extension_mismatch.then(|| Badge::outline("renamed")))
                                            .children(f.damaged.then(|| Badge::inverted("damaged"))),
                                    )
                                    .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).whitespace_normal().child(f.name.clone())),
                            )
                            .child(TextButton::new("preview-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                    )
                    .child(fact("Path", f.path.clone()))
                    .child(fact("Size", format!("{} ({} bytes)", format::bytes(f.size), f.size)))
                    .child(fact("Type", f.detected_type.clone().unwrap_or_else(|| "not classified".into())))
                    .child(fact("Created", time(f.created)))
                    .child(fact("Modified", time(f.modified)))
                    .child(fact("Accessed", time(f.accessed)))
                    .child(h_flex().pt(px(4.)).child(mode_choice("preview-mode", self.mode, move |m, w, cx| on_mode(m, w, cx)))),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .pl(px(20.))
                    .pt(px(14.))
                    .border_l_1()
                    .border_color(t.rule)
                    .gap(px(6.))
                    .child(quiet().text_size(t.size_small).child(format!("{shown}{note}")))
                    .child(div().flex_1().min_h_0().child(HexView::new("file-hex", self.bytes.clone(), 0).mode(self.mode).scroll(&self.scroll))),
            )
    }
}
