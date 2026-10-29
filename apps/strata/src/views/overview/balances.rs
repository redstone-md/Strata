//! Addresses seen on chain: the strongest sign a recovered key was really used.

use crate::format;
use crate::theme::tokens;
use crate::widgets::{Section, mono};
use gpui::{IntoElement, ParentElement, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::AddressBalance;

const MAX_ROWS: usize = 8;

pub fn section(balances: &[AddressBalance]) -> impl IntoElement {
    let t = tokens();
    let header = h_flex()
        .h(t.row_height)
        .gap(px(24.))
        .text_size(t.size_small)
        .text_color(t.text_secondary)
        .border_b_1()
        .border_color(t.row_rule)
        .child(div().flex_1().child("Address"))
        .child(div().w(px(180.)).text_right().child("Balance"))
        .child(div().w(px(120.)).text_right().child("Transactions"));
    let rows = balances.iter().take(MAX_ROWS).map(|b| {
        let funded = b.balance_sat() > 0;
        h_flex()
            .h(t.row_height)
            .gap(px(24.))
            .text_size(t.size_body)
            .border_b_1()
            .border_color(t.row_rule)
            .child(mono().flex_1().min_w_0().truncate().text_color(t.text).child(b.address.clone()))
            .child(div().w(px(180.)).text_right().text_color(if funded { t.emphasis } else { t.text_secondary }).child(format::btc(b.balance_sat())))
            .child(div().w(px(120.)).text_right().text_color(t.text).child(b.tx_count.to_string()))
    });
    let more = balances.len().saturating_sub(MAX_ROWS);
    Section::new("Addresses with on-chain history")
        .note(format::count(balances.len() as u64, "address", "addresses"))
        .child(v_flex().child(header).children(rows))
        .children((more > 0).then(|| div().text_size(t.size_small).text_color(t.text_secondary).child(format!("{more} more not shown"))))
}
