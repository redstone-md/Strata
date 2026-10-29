//! A searchable, virtualised hit list with a detail side panel. Wallets & Keys and Accounts
//! are two configurations of this one view.

use super::columns::{DiskLabels, HitColumn};
use super::delegate::HitTableDelegate;
use super::detail::HitDetailPanel;
use super::detail_tree::{self, Chain, DetailTree, TreeState};
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
use std::rc::Rc;
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
    /// Every place the selected value was found (when it was found more than once).
    places: Vec<StoredHit>,
    /// Groups the user opened or closed in the selected finding's tree.
    tree_state: TreeState,
    /// Chain lookups by address, refreshed with the table.
    chain: Rc<Chain>,
    /// One category picked from the overview, instead of all of the screen's categories.
    only: Option<HitCategory>,
    loaded_total: u64,
    /// Outcome of the last export from the detail panel.
    export_note: Option<gpui::SharedString>,
    generation: u64,
    last_load: Instant,
    /// Bumped per reload; a slower earlier load that lands late is dropped.
    loads: u64,
    loading: bool,
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
                    this.export_note = None;
                    this.places = this.selected.as_ref().map(|h| table.read(cx).delegate().places(h)).unwrap_or_default();
                    this.tree_state.clear();
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
            places: Vec::new(),
            tree_state: TreeState::new(),
            chain: Rc::new(Chain::default()),
            only: None,
            loaded_total: 0,
            export_note: None,
            generation,
            last_load: Instant::now(),
            loads: 0,
            loading: false,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    /// Rows the list shows now.
    pub fn result_count(&self, cx: &gpui::App) -> usize {
        self.table.read(cx).delegate().len()
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

    /// The one category shown instead of all, if any.
    pub fn only(&self) -> Option<HitCategory> {
        self.only
    }

    pub fn selected_id(&self) -> Option<i64> {
        self.selected.as_ref().map(|h| h.id)
    }

    /// Select a finding again by id when it is among the loaded rows.
    pub fn select_id(&mut self, id: i64, cx: &mut Context<Self>) {
        let ix = {
            let d = self.table.read(cx).delegate();
            (0..d.len()).find(|i| d.row(*i).is_some_and(|h| h.id == id))
        };
        if let Some(ix) = ix {
            self.table.update(cx, |t, cx| t.set_selected_row(ix, cx));
        }
    }

    pub fn reload(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot();
        let disks: DiskLabels = snapshot.disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
        self.loaded_total = snapshot.total_hits;
        self.chain = Rc::new(Chain::new(snapshot.checked.iter().cloned()));
        self.last_load = Instant::now();
        let wb = self.session.read(cx).workbench().clone();
        let query = self.table.read(cx).delegate().first_page();
        self.loads += 1;
        self.loading = true;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let rows = cx.background_executor().spawn(async move { wb.hits(&query).unwrap_or_default() }).await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                v.last_load = Instant::now();
                v.table.update(cx, |t, cx| {
                    t.delegate_mut().set_rows(disks, rows);
                    t.refresh(cx);
                    cx.notify();
                });
                cx.notify();
            });
        })
        .detach();
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
        } else if !self.loading && session.snapshot().total_hits != self.loaded_total && self.last_load.elapsed() >= LIVE_RELOAD {
            self.reload(cx);
        }
        cx.notify();
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
        let show_raw = self.session.read(cx).show_raw();
        let detail = self.selected.clone().map(|hit| {
            let disk = self.table.read(cx).delegate().disk_label(&hit);
            let delegate = self.table.read(cx).delegate();
            let places: Vec<(String, StoredHit)> = self.places.iter().map(|p| (delegate.disk_label(p), p.clone())).collect();
            let nodes = detail_tree::build(&hit, &disk, &places, &self.chain, show_raw);
            let this = cx.entity().downgrade();
            let tree = DetailTree::new(nodes, self.tree_state.clone(), move |path, open, _, cx| {
                let _ = this.update(cx, |b, cx| {
                    b.tree_state.insert(path, open);
                    cx.notify();
                });
            });
            let this = cx.entity().downgrade();
            let export = strata_workbench::explore::recovery::Exportable::of(&hit);
            let panel = HitDetailPanel::new(hit.clone(), tree, move |_, _, cx| {
                let _ = this.update(cx, |b, cx| {
                    b.selected = None;
                    cx.notify();
                });
            })
            .note(self.export_note.clone());
            match export {
                Some(what) => {
                    let this = cx.entity().downgrade();
                    panel.action(format!("{}…", what.action()), move |_, _, cx| {
                        let (this, hit) = (this.clone(), hit.clone());
                        crate::picker::pick_path(crate::picker::PickKind::Folder, cx, move |dest, cx| {
                            let _ = this.update(cx, |b, cx| {
                                let result = b.session.read(cx).workbench().export_finding(&hit, &dest);
                                b.export_note = Some(match result {
                                    Ok(r) => format!("Written to {}{}", r.written_to.display(), if r.partial { " (partial)" } else { "" }),
                                    Err(e) => format!("Could not export: {e}"),
                                }.into());
                                cx.notify();
                            });
                        });
                    })
                }
                None => panel,
            }
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
