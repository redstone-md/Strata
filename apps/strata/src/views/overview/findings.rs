//! Findings as a quiet two-column list; each row opens the matching table, filtered.

use super::Overview;
use crate::categories::{self, FINDINGS};
use crate::nav::Navigate;
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::Section;
use gpui::{
    Context, InteractiveElement as _, IntoElement, ParentElement, SharedString, StatefulInteractiveElement as _,
    Styled, div, px,
};
use gpui_component::{h_flex, v_flex};

pub fn section(snapshot: &Snapshot, cx: &mut Context<Overview>) -> impl IntoElement {
    let t = tokens();
    let rows = FINDINGS.iter().map(|c| {
        let n = snapshot.count(c.category);
        let category = c.category;
        let color = if n > 0 { t.emphasis } else { t.text_secondary };
        h_flex()
            .id(SharedString::from(format!("finding-{}", c.label)))
            .h(t.row_height)
            .px(px(8.))
            .justify_between()
            .border_b_1()
            .border_color(t.row_rule)
            .cursor_pointer()
            .hover(|s| s.bg(t.hover))
            .text_size(t.size_body)
            .child(div().text_color(if n > 0 { t.text } else { t.text_secondary }).child(c.label))
            .child(div().text_color(color).child(n.to_string()))
            .on_click(cx.listener(move |_, _, _, cx| {
                cx.emit(Navigate { screen: categories::screen(category), category: Some(category) });
            }))
    });
    Section::new("Findings").w(px(300.)).flex_shrink_0().child(v_flex().border_t_1().border_color(t.row_rule).children(rows))
}
