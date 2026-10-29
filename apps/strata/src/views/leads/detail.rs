//! Side panel for one lead: why it was raised, then every finding, day, address and account it
//! rests on, each with a link to where it lives.

use super::window_text;
use crate::categories;
use crate::format;
use crate::nav::{ConnectTo, Jump, Screen};
use crate::session::{Session, Snapshot};
use crate::theme::tokens;
use crate::views::timeline::kind_label;
use crate::widgets::{ClickHandler, TextButton, rule};
use gpui::{App, ClickEvent, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Catalogue, EventRecord, Lead, StoredHit};

const WIDTH: f32 = 520.;

/// The stored rows a lead points at, loaded when it is selected.
#[derive(Clone, Default)]
pub struct LinkedItems {
    hits: Vec<StoredHit>,
    events: Vec<EventRecord>,
}

impl LinkedItems {
    pub fn load(session: &Session, lead: &Lead) -> Self {
        let wb = session.workbench();
        Self { hits: wb.lead_hits(lead).unwrap_or_default(), events: wb.lead_events(lead).unwrap_or_default() }
    }
}

type JumpHandler = Rc<dyn Fn(Jump, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct LeadDetail {
    lead: Lead,
    items: LinkedItems,
    snapshot: Snapshot,
    on_jump: JumpHandler,
    on_close: ClickHandler,
}

impl LeadDetail {
    pub fn new(
        lead: Lead,
        items: LinkedItems,
        snapshot: Snapshot,
        on_jump: JumpHandler,
        on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        Self { lead, items, snapshot, on_jump, on_close: Rc::new(on_close) }
    }

    /// One linked item: a small caption, the value, and a link button.
    fn row(&self, id: impl Into<ElementId>, caption: String, value: String, data: bool, link: &'static str, jump: Jump) -> impl IntoElement {
        let t = tokens();
        let on_jump = self.on_jump.clone();
        let value = div().text_size(t.size_body).text_color(t.text).truncate().child(value);
        h_flex()
            .gap(px(12.))
            .py(px(6.))
            .items_center()
            .border_b_1()
            .border_color(t.row_rule)
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap(px(2.))
                    .child(div().text_size(t.size_small).text_color(t.text_secondary).truncate().child(caption))
                    .child(if data { value.font_family(t.font_data) } else { value }),
            )
            .child(TextButton::new(id, link).on_click(move |_, w, cx| on_jump(jump.clone(), w, cx)))
    }

    fn section(title: &'static str) -> impl IntoElement {
        let t = tokens();
        div().pt(px(16.)).pb(px(4.)).text_size(t.size_small).text_color(t.text_secondary).child(title)
    }

    fn linked(&self) -> Vec<gpui::AnyElement> {
        let mut out: Vec<gpui::AnyElement> = Vec::new();
        if !self.items.hits.is_empty() {
            out.push(Self::section("Findings").into_any_element());
            for (i, h) in self.items.hits.iter().enumerate() {
                let place = h.file_path.as_deref().map(|p| format!(" · {p}")).unwrap_or_default();
                let caption = format!("{}, {}{place}", h.hit.label, self.snapshot.disk_label(h.evidence));
                let jump = Jump::Search { screen: categories::screen(h.hit.category), text: h.hit.value.clone() };
                out.push(self.row(("lead-hit", i), caption, h.hit.value.clone(), true, "Show finding", jump).into_any_element());
            }
        }
        let addresses: Vec<&str> = self.lead.addresses().collect();
        if !addresses.is_empty() {
            out.push(Self::section("Addresses").into_any_element());
            for (i, a) in addresses.iter().enumerate() {
                let checked = self.snapshot.checked.iter().find(|b| b.address == *a);
                let caption = checked.map_or("not looked up on chain".to_string(), |b| {
                    format!("balance {}, {} transactions", format::btc(b.balance_sat()), b.tx_count)
                });
                let jump = Jump::Search { screen: Screen::Wallets, text: a.to_string() };
                out.push(self.row(("lead-addr", i), caption, a.to_string(), true, "Show finding", jump).into_any_element());
            }
        }
        let accounts: Vec<&str> = self.lead.accounts().collect();
        if !accounts.is_empty() {
            out.push(Self::section("Accounts").into_any_element());
            for (i, key) in accounts.iter().enumerate() {
                let (service, identifier) = key.split_once('|').unwrap_or(("", key));
                let service = Catalogue::shared().by_id(service).map_or(service, |e| e.name());
                let jump = Jump::Search { screen: Screen::Accounts, text: identifier.to_string() };
                out.push(self.row(("lead-acc", i), service.to_string(), identifier.to_string(), true, "Show account", jump).into_any_element());
            }
        }
        if !self.items.events.is_empty() {
            out.push(Self::section("Timeline").into_any_element());
            for (i, e) in self.items.events.iter().enumerate() {
                let ev = &e.event;
                let caption = format!("{} · {} · {}", ev.at(), kind_label(&format!("{:?}", ev.kind())), self.snapshot.disk_label(e.evidence));
                out.push(self.row(("lead-ev", i), caption, ev.title().to_string(), false, "Show day", Jump::Day(ev.at())).into_any_element());
            }
        }
        out
    }
}

impl RenderOnce for LeadDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let l = &self.lead;
        let close = self.on_close.clone();
        let mut meta = vec![format!("Score {:.0}", l.score), l.rule.label().to_string()];
        meta.extend(Some(window_text(l.window)).filter(|w| !w.is_empty()));
        let disks: Vec<String> = l.evidence.iter().map(|e| self.snapshot.disk_label(*e)).collect();
        if !disks.is_empty() {
            meta.push(disks.join(", "));
        }
        let explanation = l.explanation.iter().map(|s| {
            div().text_size(t.size_body).text_color(t.text).line_height(px(19.)).whitespace_normal().child(SharedString::from(s.clone()))
        });
        let linked = self.linked();
        let (on_jump, connections) = (self.on_jump.clone(), Jump::Connections(ConnectTo::Entity(format!("lead:{}", l.id))));
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex().p(px(20.)).pb(px(12.)).gap(px(6.)).child(
                    h_flex()
                        .justify_between()
                        .items_start()
                        .gap(px(12.))
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .min_w_0()
                                .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).whitespace_normal().child(l.title.clone()))
                                .child(div().text_size(t.size_small).text_color(t.text_secondary).child(meta.join("  ·  "))),
                        )
                        .child(
                            h_flex()
                                .gap(px(8.))
                                .child(TextButton::new("lead-connections", "Show connections").on_click(move |_, w, cx| on_jump(connections.clone(), w, cx)))
                                .child(TextButton::new("lead-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                        ),
                ),
            )
            .child(rule())
            .child(
                div().id("lead-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(12.)).child(
                    v_flex()
                        .gap(px(8.))
                        .children(explanation)
                        .child(v_flex().children(linked))
                        .child(div().h(px(8.))),
                ),
            )
    }
}
