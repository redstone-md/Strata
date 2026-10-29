//! Per-disk detail lists: volumes, and host facts recovered from the machine's artefacts.

use crate::format;
use crate::theme::tokens;
use crate::widgets::{Badge, Section, TextButton, mono};
use gpui::{App, IntoElement, ParentElement, SharedString, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{EvidenceRecord, HostFact, VolumeOrigin};

/// Width of the label cell (text, or the badge of a deleted partition).
const LABEL_WIDTH: f32 = 160.;

/// How a volume cell is set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Look {
    Text,
    /// Right-aligned number.
    Number,
    /// Right-aligned data value (hex offset).
    Offset,
}

/// One plain row of fixed-width cells.
fn row(cells: Vec<(String, f32, Look)>, header: bool) -> gpui::Div {
    let t = tokens();
    h_flex()
        .h(t.row_height)
        .gap(px(16.))
        .border_b_1()
        .border_color(t.row_rule)
        .text_size(if header { t.size_small } else { t.size_body })
        .text_color(if header { t.text_secondary } else { t.text })
        .children(cells.into_iter().map(move |(text, width, look)| {
            let cell = div().w(px(width)).flex_shrink_0().truncate().child(text);
            match look {
                Look::Text => cell,
                Look::Offset if !header => cell.text_right().font_family(t.font_data),
                _ => cell.text_right(),
            }
        }))
}

/// Volume table; `None` when nothing was recognised (the map already says so). Volumes
/// recovered from deleted partitions carry an outlined badge; every row opens in Files.
pub fn volumes(record: &EvidenceRecord, on_browse: impl Fn(u32, &mut Window, &mut App) + 'static) -> Option<impl IntoElement> {
    if record.volumes.is_empty() {
        return None;
    }
    let header = row(
        vec![
            ("Volume".into(), 56., Look::Text),
            ("Filesystem".into(), 170., Look::Text),
            ("Offset".into(), 130., Look::Offset),
            ("Size".into(), 90., Look::Number),
            ("Label".into(), LABEL_WIDTH, Look::Text),
        ],
        true,
    );
    let on_browse = Rc::new(on_browse);
    let rows = record.volumes.iter().map(|v| {
        let index = v.index;
        let browse = on_browse.clone();
        let label = if v.origin == VolumeOrigin::Recovered {
            h_flex().child(Badge::outline("deleted partition"))
        } else {
            h_flex().min_w_0().child(div().truncate().child(v.label.clone()))
        };
        row(
            vec![
                (v.index.to_string(), 56., Look::Text),
                (v.fs.name().to_string(), 170., Look::Text),
                (format::hex_offset(v.range.start()), 130., Look::Offset),
                (format::bytes(v.range.len()), 90., Look::Number),
            ],
            false,
        )
        .child(label.w(px(LABEL_WIDTH)).flex_shrink_0())
        .child(TextButton::new(SharedString::from(format!("browse-{}-{index}", record.id)), "Browse").on_click(move |_, w, cx| browse(index, w, cx)))
    });
    Some(Section::new("Volumes").child(v_flex().child(header).children(rows)))
}

/// Host facts: computer name, users, devices, wallet folders.
pub fn machine(facts: &[HostFact]) -> impl IntoElement {
    let t = tokens();
    let rows = facts.iter().map(|f| {
        h_flex()
            .min_h(t.row_height)
            .gap(px(16.))
            .border_b_1()
            .border_color(t.row_rule)
            .text_size(t.size_body)
            .child(div().w(px(150.)).flex_shrink_0().text_color(t.text_secondary).truncate().child(f.key.clone()))
            .child(mono().flex_1().min_w_0().text_color(t.text).truncate().child(f.value.clone()))
    });
    Section::new("Machine").flex_1().min_w(px(280.)).child(v_flex().border_t_1().border_color(t.row_rule).children(rows))
}
