//! Accounts: who the user was on which service. "By service" lists resolved accounts with the
//! service kind and active years from the catalogue and when each account was first and last
//! seen; "All traces" is every identity finding and service URL as found.

mod detail;
mod raw;

use crate::format;
use crate::nav::Jump;
use crate::session::Session;
use crate::theme::tokens;
use crate::views::hits::HitBrowser;
use crate::widgets::{Cell, TextButton, TextTable, flat_table};
use detail::AccountDetail;
use gpui::{
    AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window,
    div, prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Account, Catalogue, Timestamp};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    ByService,
    AllTraces,
}

pub struct AccountsView {
    session: Entity<Session>,
    table: Entity<TableState<TextTable>>,
    raw: Entity<HitBrowser>,
    tab: Tab,
    accounts: Vec<Account>,
    search: String,
    selected: Option<Account>,
    generation: u64,
    was_active: bool,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Jump> for AccountsView {}

pub(crate) fn day(t: Option<Timestamp>) -> String {
    t.map(|t| t.to_string().chars().take(10).collect()).unwrap_or_default()
}

/// Catalogue years of an account's service (`2010–2014`, `since 2013`).
pub(crate) fn years(a: &Account) -> String {
    a.service_id().and_then(|id| Catalogue::shared().by_id(id)).and_then(|e| e.years()).map(|y| y.to_string()).unwrap_or_default()
}

impl AccountsView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let raw = cx.new(|cx| HitBrowser::new(session.clone(), raw::config(), window, cx));
        let table = cx.new(|cx| {
            let columns = vec![
                ("Service", 180., Cell::Text),
                ("Kind", 120., Cell::Text),
                ("Years", 90., Cell::Text),
                ("Account", 240., Cell::Data),
                ("Type", 72., Cell::Text),
                ("First seen", 100., Cell::Data),
                ("Last seen", 100., Cell::Data),
                ("Traces", 64., Cell::Number),
                ("Disks", 150., Cell::Text),
                ("Confidence", 90., Cell::Number),
            ];
            TableState::new(TextTable::new(columns, "No accounts yet. They appear after analysis, or press Rebuild."), window, cx).col_movable(false)
        });
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event {
                    let key = table.read(cx).delegate().row_key(*ix);
                    this.selected = key.and_then(|k| this.accounts.iter().find(|a| a.key() == k.as_ref()).cloned());
                    cx.notify();
                }
            }),
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            table,
            raw,
            tab: Tab::ByService,
            accounts: Vec::new(),
            search: String::new(),
            selected: None,
            generation,
            was_active: false,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    /// The "All traces" list (the shell forwards category filters and search to it).
    pub fn raw(&self) -> &Entity<HitBrowser> {
        &self.raw
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation || (self.was_active && !active) {
            self.generation = session.generation();
            self.selected = None;
            self.reload(cx);
        }
        self.was_active = active;
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        self.search = text.trim().to_lowercase();
        self.fill(cx);
    }

    /// Show the raw traces when the overview links to a category.
    pub fn show_traces(&mut self, cx: &mut Context<Self>) {
        self.tab = Tab::AllTraces;
        cx.notify();
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        self.accounts = self.session.read(cx).workbench().accounts().unwrap_or_default();
        self.fill(cx);
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot().clone();
        let needle = self.search.clone();
        let rows: Vec<Vec<SharedString>> = self
            .accounts
            .iter()
            .filter(|a| needle.is_empty() || a.identifier().to_lowercase().contains(&needle) || a.service().to_lowercase().contains(&needle))
            .map(|a| {
                let disks = a.disks().iter().map(|e| snapshot.disk_label(*e)).collect::<Vec<_>>().join(", ");
                [
                    a.service().to_string(),
                    a.service_kind().map_or("", |k| k.label()).to_string(),
                    years(a),
                    a.identifier().to_string(),
                    a.kind().label().to_string(),
                    day(a.first_seen()),
                    day(a.last_seen()),
                    a.sources().len().to_string(),
                    disks,
                    format!("{:.0}%", a.confidence() * 100.0),
                    a.key().to_string(),
                ]
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

    fn rebuild(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        cx.spawn(async move |this, cx| {
            let _ = cx.background_executor().spawn(async move { wb.rebuild_insights() }).await;
            let _ = this.update(cx, |v, cx| v.reload(cx));
        })
        .detach();
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shown = self.table.read(cx).delegate().len() as u64;
        let funded = self.accounts.iter().filter(|a| a.holds_funds()).count() as u64;
        let tab = |id: &'static str, label: &'static str, which: Tab, cx: &mut Context<Self>| {
            let button = TextButton::new(id, label).on_click(cx.listener(move |this, _, _, cx| {
                this.tab = which;
                cx.notify();
            }));
            if self.tab == which { button.strong() } else { button }
        };
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Accounts"))
            .child(div().text_color(t.text_secondary).child(format!(
                "{}, {funded} on services that hold funds",
                format::count(shown, "account", "accounts")
            )))
            .child(div().flex_1())
            .child(tab("acc-by-service", "By service", Tab::ByService, cx))
            .child(tab("acc-traces", "All traces", Tab::AllTraces, cx))
            .child(TextButton::new("acc-rebuild", "Rebuild").on_click(cx.listener(|this, _, _, cx| this.rebuild(cx))))
    }
}

impl Render for AccountsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let header = h_flex().pr(t.gutter).child(div().flex_1().child(self.header(cx)));
        if self.tab == Tab::AllTraces {
            return v_flex().size_full().gap(px(12.)).child(header).child(div().flex_1().min_h_0().size_full().child(self.raw.clone())).into_any_element();
        }
        let detail = self.selected.clone().map(|a| {
            let this = cx.entity().downgrade();
            let jump_to = this.clone();
            let on_jump = Rc::new(move |jump: Jump, _: &mut Window, cx: &mut gpui::App| {
                let _ = jump_to.update(cx, |_, cx| cx.emit(jump));
            });
            AccountDetail::new(a, self.session.read(cx).snapshot().clone(), on_jump, move |_, _, cx| {
                let _ = this.update(cx, |v, cx| {
                    v.selected = None;
                    cx.notify();
                });
            })
        });
        v_flex()
            .size_full()
            .gap(px(12.))
            .child(header)
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .items_start()
                    .child(div().flex_1().min_w_0().h_full().pr(t.gutter).child(flat_table(&self.table)))
                    .when_some(detail, |el, d| el.child(d)),
            )
            .into_any_element()
    }
}
