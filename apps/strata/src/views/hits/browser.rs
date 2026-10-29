//! A searchable, virtualised hit list with a detail side panel. Wallets & Keys and Accounts
//! are two configurations of this one view.

use super::columns::{DiskLabels, HitColumn};
use super::delegate::HitTableDelegate;
use super::detail::HitDetailPanel;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::GlassCard;
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    Window, div, prelude::FluentBuilder as _,
};
use gpui_component::h_flex;
use gpui_component::table::{DataTable, TableEvent, TableState};
use std::time::{Duration, Instant};
use strata_workbench::{HitCategory, HitQuery, StoredHit};

/// Minimum spacing between automatic reloads while a scan keeps adding hits.
const LIVE_RELOAD: Duration = Duration::from_secs(3);

pub struct BrowserConfig {
    pub title: &'static str,
    pub subtitle: &'static str,
    pub categories: Vec<HitCategory>,
    pub columns: Vec<HitColumn>,
    pub initial_sort: Option<HitColumn>,
}

pub struct HitBrowser {
    session: Entity<Session>,
    config: BrowserConfig,
    table: Entity<TableState<HitTableDelegate>>,
    selected: Option<StoredHit>,
    loaded_total: u64,
    generation: u64,
    last_load: Instant,
    _subscriptions: Vec<Subscription>,
}

impl HitBrowser {
    pub fn new(session: Entity<Session>, config: BrowserConfig, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let workbench = session.read(cx).workbench().clone();
        let query = HitQuery { categories: config.categories.clone(), ..HitQuery::default() };
        let mut delegate = HitTableDelegate::new(workbench, config.columns.clone(), query);
        if let Some(col) = config.initial_sort {
            delegate.set_initial_sort(col);
        }
        let table = cx.new(|cx| TableState::new(delegate, window, cx).col_movable(false));
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event {
                    this.selected = table.read(cx).delegate().row(*ix).cloned();
                    cx.notify();
                }
            }),
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            config,
            table,
            selected: None,
            loaded_total: 0,
            generation,
            last_load: Instant::now(),
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        self.table.update(cx, |t, _| t.delegate_mut().set_text(text));
        self.reload(cx);
    }

    pub fn reload(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot();
        let disks: DiskLabels = snapshot.disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
        self.loaded_total = snapshot.total_hits;
        self.last_load = Instant::now();
        self.table.update(cx, |t, cx| {
            t.delegate_mut().reload(disks);
            t.refresh(cx);
            cx.notify();
        });
        cx.notify();
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        if session.generation() != self.generation {
            self.generation = session.generation();
            let wb = session.workbench().clone();
            self.selected = None;
            self.table.update(cx, |t, _| t.delegate_mut().set_workbench(wb));
            self.reload(cx);
        } else if session.snapshot().total_hits != self.loaded_total && self.last_load.elapsed() >= LIVE_RELOAD {
            self.reload(cx);
        }
    }

    fn count_label(&self, cx: &Context<Self>) -> SharedString {
        let d = self.table.read(cx).delegate();
        let more = if d.has_more_rows() { "+ (scroll for more)" } else { "" };
        format!("{} {}{more} · {}", d.len(), if d.len() == 1 { "result" } else { "results" }, self.config.subtitle).into()
    }
}

impl Render for HitBrowser {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let detail = self.selected.clone().map(|hit| {
            let disk = self.table.read(cx).delegate().disk_label(&hit);
            let this = cx.entity().downgrade();
            HitDetailPanel::new(hit, disk, move |_, _, cx| {
                let _ = this.update(cx, |b, cx| {
                    b.selected = None;
                    cx.notify();
                });
            })
        });
        h_flex()
            .size_full()
            .items_start()
            .gap(t.gap)
            .child(
                GlassCard::new()
                    .title(self.config.title)
                    .subtitle(self.count_label(cx))
                    .flex_1()
                    .h_full()
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .size_full()
                            .child(DataTable::new(&self.table).stripe(true).bordered(false)),
                    ),
            )
            .when_some(detail, |el, d| el.child(d))
    }
}
