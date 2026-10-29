//! Leads: ranked hypotheses of where coins and keys may be ("what may fit where"), each with
//! the facts behind it and links to the findings, days and accounts it rests on.

mod detail;

use crate::format;
use crate::nav::Jump;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Cell, TextButton, TextTable, flat_table, quiet};
use detail::{LeadDetail, LinkedItems};
use gpui::{
    AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window,
    div, prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Lead, Timestamp};

pub struct LeadsView {
    session: Entity<Session>,
    table: Entity<TableState<TextTable>>,
    leads: Vec<Lead>,
    search: String,
    selected: Option<(Lead, LinkedItems)>,
    /// A rebuild or chain fetch running in the background.
    busy: Option<&'static str>,
    status: Option<String>,
    generation: u64,
    was_active: bool,
    /// The period of interest the list was last filled with.
    period: strata_workbench::Period,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Jump> for LeadsView {}

fn day(t: Timestamp) -> String {
    t.to_string().chars().take(10).collect()
}

/// `2011-06-14` or `2011-06-14 to 2012-01-05`.
pub(crate) fn window_text(w: Option<(Timestamp, Timestamp)>) -> String {
    match w {
        Some((a, b)) if day(a) == day(b) => day(a),
        Some((a, b)) => format!("{} to {}", day(a), day(b)),
        None => String::new(),
    }
}

impl LeadsView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let table = cx.new(|cx| {
            TableState::new(
                TextTable::new(
                    vec![("Score", 64., Cell::Number), ("Lead", 520., Cell::Text), ("Kind", 200., Cell::Text), ("Period", 240., Cell::Data), ("Disks", 200., Cell::Text)],
                    "No leads yet. They appear after the balance check, or press Rebuild.",
                ),
                window,
                cx,
            )
            .col_movable(false)
        });
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event {
                    let key = table.read(cx).delegate().row_key(*ix);
                    this.select(key, cx);
                }
            }),
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            table,
            leads: Vec::new(),
            search: String::new(),
            selected: None,
            busy: None,
            status: None,
            generation,
            was_active: false,
            period: strata_workbench::Period::ALL,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        let switched = session.generation() != self.generation;
        if switched || (self.was_active && !active) {
            self.generation = session.generation();
            self.selected = None;
            self.reload(cx);
        }
        self.was_active = active;
        if self.session.read(cx).period() != self.period {
            self.fill(cx);
        }
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        self.search = text.trim().to_lowercase();
        self.fill(cx);
    }

    pub fn reload(&mut self, cx: &mut Context<Self>) {
        self.leads = self.session.read(cx).workbench().leads().unwrap_or_default();
        self.fill(cx);
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot().clone();
        let needle = self.search.clone();
        // The case's period of interest; undated items stay.
        let period = self.session.read(cx).period();
        self.period = period;
        let rows: Vec<Vec<SharedString>> = self
            .leads
            .iter()
            .filter(|l| needle.is_empty() || l.title.to_lowercase().contains(&needle) || l.text().to_lowercase().contains(&needle))
            .filter(|l| period.overlaps(l.window.map(|w| w.0), l.window.map(|w| w.1)))
            .map(|l| {
                let disks = l.evidence.iter().map(|e| snapshot.disk_label(*e)).collect::<Vec<_>>().join(", ");
                [format!("{:.0}", l.score), l.title.clone(), l.rule.label().to_string(), window_text(l.window), disks, l.id.clone()]
                    .into_iter()
                    .map(SharedString::from)
                    .collect()
            })
            .collect();
        self.table.update(cx, |t, cx| {
            t.delegate_mut().set_rows(rows);
            t.refresh(cx);
            cx.notify();
        });
        cx.notify();
    }

    fn select(&mut self, key: Option<SharedString>, cx: &mut Context<Self>) {
        let lead = key.and_then(|k| self.leads.iter().find(|l| l.id == k.as_ref()).cloned());
        self.selected = lead.map(|l| {
            let items = LinkedItems::load(self.session.read(cx), &l);
            (l, items)
        });
        cx.notify();
    }

    /// Run `work` on a background thread, then reload with its message.
    fn run(&mut self, label: &'static str, work: impl FnOnce(&strata_workbench::Workbench) -> String + Send + 'static, cx: &mut Context<Self>) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some(label);
        self.status = None;
        let wb = self.session.read(cx).workbench().clone();
        cx.spawn(async move |this, cx| {
            let message = cx.background_executor().spawn(async move { work(&wb) }).await;
            let _ = this.update(cx, |v, cx| {
                v.busy = None;
                v.status = Some(message);
                v.reload(cx);
            });
        })
        .detach();
        cx.notify();
    }

    fn rebuild(&mut self, cx: &mut Context<Self>) {
        self.run(
            "Rebuilding leads",
            |wb| match wb.rebuild_insights() {
                Ok((a, l)) => format!("{} and {}", format::count(a as u64, "account", "accounts"), format::count(l as u64, "lead", "leads")),
                Err(e) => format!("Rebuild failed: {e}"),
            },
            cx,
        );
    }

    fn fetch(&mut self, cx: &mut Context<Self>) {
        self.run(
            "Fetching chain history",
            |wb| match wb.fetch_histories() {
                Ok((ok, failed)) => format!("{} fetched, {failed} failed", format::count(ok as u64, "address history", "address histories")),
                Err(e) => format!("Chain history failed: {e}"),
            },
            cx,
        );
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shown = self.table.read(cx).delegate().len() as u64;
        let count = if shown as usize == self.leads.len() {
            format::count(shown, "lead", "leads")
        } else {
            format!("{shown} of {}", format::count(self.leads.len() as u64, "lead", "leads"))
        };
        let note = self.busy.map(|b| format!("{b}…")).or_else(|| self.status.clone());
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Leads"))
            .child(div().text_color(t.text_secondary).child(count))
            .children(note.map(|n| quiet().child(n)))
            .child(div().flex_1())
            .child(TextButton::new("leads-fetch", "Fetch chain history").on_click(cx.listener(|this, _, _, cx| this.fetch(cx))))
            .child(TextButton::new("leads-rebuild", "Rebuild").on_click(cx.listener(|this, _, _, cx| this.rebuild(cx))))
    }
}

impl Render for LeadsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let detail = self.selected.clone().map(|(lead, items)| {
            let this = cx.entity().downgrade();
            let jump_to = this.clone();
            let on_jump = Rc::new(move |jump: Jump, _: &mut Window, cx: &mut gpui::App| {
                let _ = jump_to.update(cx, |_, cx| cx.emit(jump));
            });
            LeadDetail::new(lead, items, self.session.read(cx).snapshot().clone(), on_jump, move |_, _, cx| {
                let _ = this.update(cx, |v, cx| {
                    v.selected = None;
                    cx.notify();
                });
            })
        });
        h_flex()
            .size_full()
            .items_start()
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .gap(px(12.))
                    .pr(t.gutter)
                    .child(self.header(cx))
                    .child(div().flex_1().min_h_0().size_full().child(flat_table(&self.table))),
            )
            .when_some(detail, |el, d| el.child(d))
    }
}
