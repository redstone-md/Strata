//! Every host fact of a disk, behind a toggle: one line per key with its counts and first
//! distinct values; a key opens to show up to [`OPEN_VALUES`] values. Never an unbounded list.

use crate::theme::tokens;
use crate::widgets::{TextButton, mono, quiet};
use gpui::{App, IntoElement, ParentElement, SharedString, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::FactGroup;

/// Opens or closes one key's longer list.
pub type KeyToggle = Rc<dyn Fn(String, &mut Window, &mut App)>;

/// Values shown under a closed key.
const CLOSED_VALUES: usize = 2;
/// Values shown under an open key (also what is loaded per key).
pub const OPEN_VALUES: usize = 40;

fn value_row(value: &str, count: u64, source: &str) -> impl IntoElement {
    let t = tokens();
    h_flex()
        .min_h(px(22.))
        .gap(px(12.))
        .pl(px(24.))
        .text_size(t.size_body)
        .child(mono().flex_1().min_w_0().truncate().text_color(t.text).child(value.to_string()))
        .children((count > 1).then(|| div().flex_shrink_0().text_color(t.text_secondary).child(format!("×{count}"))))
        .child(div().flex_shrink_0().max_w(px(220.)).truncate().text_size(t.size_small).text_color(t.text_secondary).child(source.to_string()))
}

/// The grouped facts; `open` says which keys show their longer list, `on_toggle` flips one.
pub fn list(id: u32, groups: &[FactGroup], open: &[String], on_toggle: KeyToggle) -> impl IntoElement {
    let t = tokens();
    if groups.is_empty() {
        return v_flex().child(quiet().child("No host facts stored for this disk."));
    }
    let total: u64 = groups.iter().map(|g| g.total).sum();
    let title = h_flex()
        .gap_3()
        .items_baseline()
        .pb(px(6.))
        .child(div().text_size(t.size_body).font_weight(t.semibold).text_color(t.emphasis).child("All host facts"))
        .child(quiet().child(format!("{total} stored under {} keys, repeats folded", groups.len())));
    v_flex().pt(px(8.)).child(title).child(v_flex().border_t_1().border_color(t.row_rule).children(groups.iter().map(|g| {
        let is_open = open.contains(&g.key);
        let shown = if is_open { OPEN_VALUES } else { CLOSED_VALUES };
        let hidden = g.distinct.saturating_sub(shown.min(g.values.len()) as u64);
        let toggle = on_toggle.clone();
        let key = g.key.clone();
        let button = (g.distinct > CLOSED_VALUES as u64).then(|| {
            let label = match (is_open, g.distinct > OPEN_VALUES as u64) {
                (true, _) => "Fewer".to_string(),
                (false, true) => format!("Show {OPEN_VALUES} of {}", g.distinct),
                (false, false) => format!("Show all {}", g.distinct),
            };
            TextButton::new(SharedString::from(format!("fact-{id}-{}", g.key)), label).on_click(move |_, w, cx| toggle(key.clone(), w, cx))
        });
        v_flex()
            .py(px(4.))
            .border_b_1()
            .border_color(t.row_rule)
            .child(
                h_flex()
                    .min_h(px(26.))
                    .gap(px(12.))
                    .text_size(t.size_body)
                    .child(mono().w(px(200.)).flex_shrink_0().truncate().text_color(t.emphasis).child(g.key.clone()))
                    .child(div().flex_1().text_color(t.text_secondary).child(format!("{} stored · {} distinct", g.total, g.distinct)))
                    .children(button),
            )
            .children(g.values.iter().take(shown).map(|(v, n, s)| value_row(v, *n, s)))
            .children((hidden > 0 && is_open).then(|| quiet().pl(px(24.)).text_size(t.size_small).child(format!("{hidden} more values not shown"))))
    })))
}
