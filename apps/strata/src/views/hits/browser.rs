//! A searchable, virtualised hit list with a detail side panel. Wallets & Keys and Accounts
//! are two configurations of this one view.

use super::columns::{DiskLabels, HitColumn};
use super::delegate::HitTableDelegate;
use super::detail::HitDetailPanel;
use crate::categories;
use crate::format;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{TextButton, flat_table};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use gpui_component::table::{TableEvent, TableState};
use std::time::{Duration, Instant};
use strata_workbench::{HitCategory, HitQuery, StoredHit};

/// Minimum spacing between automatic reloads while a scan keeps adding hits.
const LIVE_RELOAD: Duration = Duration::from_secs(3);

pub struct BrowserConfig {
    pub title: &'static str,
    pub categories: Vec<HitCategory>,
    pub columns: Vec<HitColumn>,
    pub initial_sort: Option<HitColumn>,
}

pub struct HitBrowser {
    session: Entity<Session>,
    config: BrowserConfig,
    table: Entity<TableState<HitTableDelegate>>,
    selected: Option<StoredHit>,
    /// One category picked from the overview, instead of all of the screen's categories.
    only: Option<HitCategory>,
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
            only: None,
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

    /// Show one category only, or (`None`) every category of this screen.
    pub fn show_category(&mut self, only: Option<HitCategory>, cx: &mut Context<Self>) {
        self.only = only.filter(|c| self.config.categories.contains(c));
        let categories = self.only.map_or_else(|| self.config.categories.clone(), |c| vec![c]);
        self.selected = None;
        self.table.update(cx, |t, _| t.delegate_mut().set_categories(categories));
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

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let d = self.table.read(cx).delegate();
        let n = d.len() as u64;
        let count = if d.has_more_rows() { format!("first {n}, scroll for more") } else { format::count(n, "result", "results") };
        let filter = self.only.map(|c| {
            h_flex()
                .gap(px(8.))
                .child(div().text_color(t.text).child(format!("Only {}", categories::label(c).to_lowercase())))
                .child(TextButton::new("show-all", "Show all").on_click(cx.listener(|this, _, _, cx| this.show_category(None, cx))))
        });
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child(self.config.title))
            .child(div().text_color(t.text_secondary).child(count))
            .children(filter)
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
