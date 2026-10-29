//! Wallet trails, the second page of the Leads screen: one row per wallet-relevant file with
//! its fate (live, moved, deleted, archived, mailed, carved, not found), and beside the list
//! the chain of evidence of the selected one. Built on a background thread (a few seconds on
//! a large case) whenever the case, its period of interest or its jobs change.

use super::trail_detail::TrailDetail;
use super::window_text;
use crate::format;
use crate::nav::Jump;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Cell, TextButton, TextTable, flat_table, loading_edge, quiet};
use gpui::{
    AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use std::sync::Arc;
use strata_workbench::{Period, Trail};

pub struct TrailsView {
    session: Entity<Session>,
    table: Entity<TableState<TextTable>>,
    trails: Arc<Vec<Trail>>,
    search: String,
    selected: Option<Trail>,
    /// Bumped per load; a slower earlier load that lands late is dropped.
    loads: u64,
    loading: bool,
    failed: Option<String>,
    generation: u64,
    was_active: bool,
    period: Period,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Jump> for TrailsView {}

impl TrailsView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let table = cx.new(|cx| {
            TableState::new(
                TextTable::new(
                    vec![
                        ("Score", 64., Cell::Number),
                        ("File", 260., Cell::Data),
                        ("Fate", 190., Cell::Text),
                        ("Sure", 64., Cell::Number),
                        ("Steps", 64., Cell::Number),
                        ("Period", 220., Cell::Data),
                        ("Disks", 180., Cell::Text),
                    ],
                    "No wallet trails: no trace of a wallet file in this case or this period.",
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
        Self {
            session,
            table,
            trails: Arc::new(Vec::new()),
            search: String::new(),
            selected: None,
            loads: 0,
            loading: false,
            failed: None,
            generation,
            was_active: false,
            period: Period::ALL,
            _subscriptions: subscriptions,
        }
    }

    /// Load when first shown; later loads follow the session.
    pub fn ensure_loaded(&mut self, cx: &mut Context<Self>) {
        if self.loads == 0 {
            self.reload(cx);
        }
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        if self.loads == 0 {
            return;
        }
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            self.selected = None;
            self.reload(cx);
        } else if session.period() != self.period || self.was_active && !active {
            self.reload(cx);
        }
        self.was_active = active;
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        self.search = text.trim().to_lowercase();
        self.fill(cx);
    }

    /// Build the trails for the case's period on a background thread, then show them.
    pub fn reload(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let wb = session.workbench().clone();
        self.period = session.period();
        let period = self.period;
        self.loads += 1;
        self.loading = true;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let result = cx.background_executor().spawn(async move { wb.wallet_trails(period) }).await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                match result {
                    Ok(trails) => {
                        v.failed = None;
                        v.selected = v.selected.take().and_then(|s| trails.iter().find(|t| t.id == s.id).cloned());
                        v.trails = Arc::new(trails);
                    }
                    Err(e) => v.failed = Some(format!("Could not build the trails: {e}")),
                }
                v.fill(cx);
            });
        })
        .detach();
        cx.notify();
    }

    fn fill(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot().clone();
        let needle = self.search.clone();
        let rows: Vec<Vec<SharedString>> = self
            .trails
            .iter()
            .filter(|t| needle.is_empty() || t.name.to_lowercase().contains(&needle) || t.origin.to_lowercase().contains(&needle) || t.verdict.fate.label().contains(&needle))
            .map(|t| {
                let disks = t.evidence.iter().map(|e| snapshot.disk_label(*e)).collect::<Vec<_>>().join(", ");
                [
                    format!("{:.0}", t.score),
                    t.name.clone(),
                    t.verdict.fate.label().to_string(),
                    format!("{:.0}%", t.verdict.confidence * 100.0),
                    t.steps.len().to_string(),
                    window_text(t.window),
                    disks,
                    t.id.clone(),
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

    fn select(&mut self, key: Option<SharedString>, cx: &mut Context<Self>) {
        self.selected = key.and_then(|k| self.trails.iter().find(|t| t.id == k.as_ref()).cloned());
        cx.notify();
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shown = self.table.read(cx).delegate().len() as u64;
        let total = self.trails.len() as u64;
        let count = if shown == total { format::count(shown, "trail", "trails") } else { format!("{shown} of {}", format::count(total, "trail", "trails")) };
        let note = if self.loading { Some("Following traces across the disks…".to_string()) } else { self.failed.clone() };
        h_flex()
            .h(px(28.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_color(t.text_secondary).child(count))
            .children(note.map(|n| quiet().child(n)))
            .child(div().flex_1())
            .child(TextButton::new("trails-rebuild", "Rebuild trails").on_click(cx.listener(|this, _, _, cx| this.reload(cx))))
    }
}

impl Render for TrailsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let detail = self.selected.clone().map(|trail| {
            let this = cx.entity().downgrade();
            let jump_to = this.clone();
            let on_jump = Rc::new(move |jump: Jump, _: &mut Window, cx: &mut gpui::App| {
                let _ = jump_to.update(cx, |_, cx| cx.emit(jump));
            });
            TrailDetail::new(trail, self.session.read(cx).snapshot().clone(), on_jump, move |_, _, cx| {
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
                    .gap(px(8.))
                    .pr(t.gutter)
                    .child(self.header(cx))
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_h_0()
                            .size_full()
                            .child(flat_table(&self.table))
                            .when(self.loading, |el| el.child(loading_edge("trails-loading"))),
                    ),
            )
            .when_some(detail, |el, d| el.child(d))
    }
}
