//! Addresses seen on chain: the strongest sign a recovered key was really used.

use crate::format;
use crate::nav::{Jump, Screen};
use crate::theme::tokens;
use crate::widgets::{Section, TextButton, mono};
use gpui::{ClipboardItem, IntoElement, ParentElement, Styled, WeakEntity, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::AddressBalance;

const MAX_ROWS: usize = 8;
/// Where "Explorer" opens an address.
const EXPLORER: &str = "https://mempool.space/address/";

pub fn section(balances: &[AddressBalance], overview: WeakEntity<super::Overview>) -> impl IntoElement {
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
        .child(div().w(px(120.)).text_right().child("Transactions"))
        .child(div().w(px(260.)));
    let rows = balances.iter().take(MAX_ROWS).enumerate().map(|(i, b)| {
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
            .child(actions(i, &b.address, overview.clone()))
    });
    let more = balances.len().saturating_sub(MAX_ROWS);
    Section::new("Addresses with on-chain history")
        .note(format::count(balances.len() as u64, "address", "addresses"))
        .child(v_flex().child(header).children(rows))
        .children((more > 0).then(|| div().text_size(t.size_small).text_color(t.text_secondary).child(format!("{more} more not shown"))))
}

/// Copy the address, open it in a block explorer, or show the findings it came from.
fn actions(i: usize, address: &str, overview: WeakEntity<super::Overview>) -> impl IntoElement {
    let (copy, open, find) = (address.to_string(), format!("{EXPLORER}{address}"), address.to_string());
    h_flex()
        .w(px(260.))
        .justify_end()
        .gap(px(12.))
        .child(TextButton::new(("balance-copy", i), "Copy").on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))))
        .child(TextButton::new(("balance-open", i), "Explorer").on_click(move |_, _, cx| cx.open_url(&open)))
        .child(TextButton::new(("balance-find", i), "Show key").on_click(move |_, _, cx| {
            let _ = overview.update(cx, |_, cx| cx.emit(Jump::Search { screen: Screen::Wallets, text: find.clone() }));
        }))
}
