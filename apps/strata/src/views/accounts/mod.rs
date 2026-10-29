//! Accounts: who the owner was and where they had accounts that may hold money or wallet
//! backups. "By owner" lists the accounts some trace shows in use (saved password, mail
//! client, Windows user, cookie...), by section and evidence strength; addresses only seen in
//! data (mail headers, pages, free space) wait in a collapsed group, and bulk ones (dumps,
//! lists) only show on request. "All traces" is every identity finding and service URL.
//! Everything loads off the UI thread; the search box and the case period filter both lists.

mod detail;
mod list;
mod raw;

use crate::format;
use crate::nav::Jump;
use crate::session::Session;
use crate::theme::tokens;
use crate::views::hits::HitBrowser;
use crate::widgets::{Check, TextButton, TextTable, flat_table, loading_edge};
use detail::{AccountDetail, Detail};
use gpui::{
    AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use list::{Pick, Rail};
use std::rc::Rc;
use strata_workbench::{AccountQuery, AccountRow, Period, ServiceGroup, Timestamp};

/// Rows the "Other addresses seen" list loads at most (narrow with the search box).
const SEEN_LIMIT: usize = 5_000;
/// Places listed for a bare sighting.
const SIGHTING_PLACES: usize = 50;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    ByOwner,
    AllTraces,
}

pub struct AccountsView {
    session: Entity<Session>,
    used_table: Entity<TableState<TextTable>>,
    seen_table: Entity<TableState<TextTable>>,
    raw: Entity<HitBrowser>,
    tab: Tab,
    pick: Pick,
    show_bulk: bool,
    /// Every used account (few), filtered in memory.
    used: Vec<AccountRow>,
    /// The loaded page of seen accounts and addresses.
    seen: Vec<AccountRow>,
    /// Seen rows matching search and period (`None` while counting).
    seen_total: Option<u64>,
    /// Accounts were resolved by an older version: a rebuild sorts them by use.
    stale: bool,
    search: String,
    period: Period,
    detail: Option<Detail>,
    loading: bool,
    rebuilding: bool,
    loads: u64,
    seen_loads: u64,
    picks: u64,
    generation: u64,
    was_active: bool,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Jump> for AccountsView {}

pub(crate) fn day(t: Option<Timestamp>) -> String {
    t.map(|t| t.to_string().chars().take(10).collect()).unwrap_or_default()
}

impl AccountsView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let raw = cx.new(|cx| HitBrowser::new(session.clone(), raw::config(), window, cx));
        let used_table = cx.new(|cx| {
            let empty = "No accounts used by the owner here. They appear after analysis, or press Rebuild.";
            TableState::new(TextTable::new(list::used_columns(), empty), window, cx).col_movable(false)
        });
        let seen_table = cx.new(|cx| {
            let empty = "No other addresses for this search and period.";
            TableState::new(TextTable::new(list::seen_columns(), empty), window, cx).col_movable(false)
        });
        let subscriptions = vec![
            cx.subscribe_in(&used_table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event {
                    let key = table.read(cx).delegate().row_key(*ix);
                    this.select(key, cx);
                }
            }),
            cx.subscribe_in(&seen_table, window, |this, table, event: &TableEvent, _, cx| {
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
            used_table,
            seen_table,
            raw,
            tab: Tab::ByOwner,
            pick: Pick::All,
            show_bulk: false,
            used: Vec::new(),
            seen: Vec::new(),
            seen_total: None,
            stale: false,
            search: String::new(),
            period: Period::ALL,
            detail: None,
            loading: false,
            rebuilding: false,
            loads: 0,
            seen_loads: 0,
            picks: 0,
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
            self.detail = None;
            self.reload(cx);
        }
        self.was_active = active;
        if self.session.read(cx).period() != self.period {
            self.period = self.session.read(cx).period();
            self.fill_used(cx);
            self.load_seen(cx);
        }
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        let search = text.trim().to_lowercase();
        if search == self.search {
            return;
        }
        self.search = search;
        self.fill_used(cx);
        self.load_seen(cx);
    }

    /// Show the raw traces when the overview links to a category.
    pub fn show_traces(&mut self, cx: &mut Context<Self>) {
        self.tab = Tab::AllTraces;
        cx.notify();
    }

    /// Load every used account off the UI thread, then the seen list.
    fn reload(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        self.period = self.session.read(cx).period();
        self.loads += 1;
        self.loading = true;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let (used, stale) = cx
                .background_executor()
                .spawn(async move { (wb.account_rows(&AccountQuery::default()).unwrap_or_default(), wb.accounts_need_rebuild().unwrap_or(false)) })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                v.used = used;
                v.stale = stale;
                v.fill_used(cx);
            });
        })
        .detach();
        self.load_seen(cx);
        cx.notify();
    }

    /// Count the seen rows for search and period; load them when that list is open.
    fn load_seen(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        let open = self.pick == Pick::Seen;
        let query = AccountQuery {
            seen: true,
            include_bulk: self.show_bulk,
            text: Some(self.search.clone()).filter(|s| !s.is_empty()),
            period: Some(self.period),
            limit: SEEN_LIMIT,
            ..Default::default()
        };
        self.seen_loads += 1;
        self.seen_total = None;
        let ticket = self.seen_loads;
        cx.spawn(async move |this, cx| {
            let (rows, total) = cx
                .background_executor()
                .spawn(async move {
                    let rows = if open { wb.account_rows(&query).unwrap_or_default() } else { Vec::new() };
                    (rows, wb.account_count(&query).unwrap_or_default())
                })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.seen_loads != ticket {
                    return;
                }
                v.seen_total = Some(total);
                if open {
                    v.seen = rows;
                    v.fill_seen(cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn visible_used(&self) -> impl Iterator<Item = &AccountRow> {
        let (needle, period) = (self.search.as_str(), self.period);
        self.used.iter().filter(move |r| list::matches(r, needle, period))
    }

    fn fill_used(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot().clone();
        let pick = self.pick;
        let rows: Vec<Vec<SharedString>> = self
            .visible_used()
            .filter(|r| match pick {
                Pick::Group(g) => r.group == g,
                _ => true,
            })
            .map(|r| list::used_row(&snapshot, r))
            .collect();
        self.used_table.update(cx, |t, cx| {
            t.delegate_mut().set_rows(rows);
            t.refresh(cx);
            cx.notify();
        });
        cx.notify();
    }

    fn fill_seen(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot().clone();
        let rows: Vec<Vec<SharedString>> = self.seen.iter().map(|r| list::seen_row(&snapshot, r)).collect();
        self.seen_table.update(cx, |t, cx| {
            t.delegate_mut().set_rows(rows);
            t.refresh(cx);
            cx.notify();
        });
    }

    fn set_pick(&mut self, pick: Pick, cx: &mut Context<Self>) {
        if pick == self.pick {
            return;
        }
        self.pick = pick;
        self.detail = None;
        if pick == Pick::Seen {
            self.load_seen(cx);
        } else {
            self.seen.clear();
            self.fill_used(cx);
        }
        cx.notify();
    }

    fn toggle_bulk(&mut self, cx: &mut Context<Self>) {
        self.show_bulk = !self.show_bulk;
        self.load_seen(cx);
    }

    /// Show a row's evidence: the account and its sightings, or the places a bare address
    /// was found; loaded off the UI thread.
    fn select(&mut self, key: Option<SharedString>, cx: &mut Context<Self>) {
        let Some(row) = key.and_then(|k| self.used.iter().chain(&self.seen).find(|r| r.key == k.as_ref()).cloned()) else { return };
        let wb = self.session.read(cx).workbench().clone();
        self.picks += 1;
        let ticket = self.picks;
        self.detail = Some(Detail::Account { row: row.clone(), account: None, mention: None });
        cx.spawn(async move |this, cx| {
            let detail = cx
                .background_executor()
                .spawn(async move {
                    let mention = if row.kind == "e-mail" { wb.mention(&row.identifier).ok().flatten() } else { None };
                    if row.mention_only {
                        let hits = mention.as_ref().map(|m| wb.mention_hits(m, SIGHTING_PLACES).unwrap_or_default()).unwrap_or_default();
                        Detail::Sighting { row, mention, hits }
                    } else {
                        let account = wb.account(&row.key).ok().flatten();
                        Detail::Account { row, account, mention }
                    }
                })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.picks == ticket {
                    v.detail = Some(detail);
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    /// The finding behind a trace, in the "All traces" list.
    fn show_finding(&mut self, value: &str, cx: &mut Context<Self>) {
        self.tab = Tab::AllTraces;
        self.raw.update(cx, |b, cx| b.set_search(value, cx));
        cx.notify();
    }

    fn rebuild(&mut self, cx: &mut Context<Self>) {
        if self.rebuilding {
            return;
        }
        self.rebuilding = true;
        let wb = self.session.read(cx).workbench().clone();
        cx.spawn(async move |this, cx| {
            let _ = cx.background_executor().spawn(async move { wb.rebuild_insights() }).await;
            let _ = this.update(cx, |v, cx| {
                v.rebuilding = false;
                v.detail = None;
                v.reload(cx);
            });
        })
        .detach();
        cx.notify();
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let used: Vec<&AccountRow> = self.visible_used().collect();
        let secrets = used.iter().filter(|r| r.secret).count() as u64;
        let mut summary = format!("{} used by the owner", format::count(used.len() as u64, "account", "accounts"));
        if secrets > 0 {
            summary += &format!(", {secrets} with a saved password");
        }
        if let Some(n) = self.seen_total {
            summary += &format!(" · {} only seen", format::count(n, "address", "addresses"));
        }
        let tab = |id: &'static str, label: &'static str, which: Tab, cx: &mut Context<Self>| {
            let button = TextButton::new(id, label).on_click(cx.listener(move |this, _, _, cx| {
                this.tab = which;
                cx.notify();
            }));
            if self.tab == which { button.strong() } else { button }
        };
        let rebuild = TextButton::new("acc-rebuild", if self.rebuilding { "Rebuilding…" } else { "Rebuild" })
            .on_click(cx.listener(|this, _, _, cx| this.rebuild(cx)));
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Accounts"))
            .child(div().min_w_0().truncate().text_color(t.text_secondary).child(summary))
            .child(div().flex_1())
            .child(tab("acc-by-owner", "By owner", Tab::ByOwner, cx))
            .child(tab("acc-traces", "All traces", Tab::AllTraces, cx))
            .child(rebuild)
    }

    fn rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let used: Vec<&AccountRow> = self.visible_used().collect();
        let groups = ServiceGroup::ALL.iter().map(|g| (*g, used.iter().filter(|r| r.group == *g).count() as u64)).collect();
        let this = cx.entity().downgrade();
        Rail::new(self.pick, used.len() as u64, groups, self.seen_total, move |pick, _, cx| {
            let _ = this.update(cx, |v, cx| v.set_pick(pick, cx));
        })
    }

    /// Above the seen list: what it holds and the bulk switch.
    fn seen_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shown = self.seen.len() as u64;
        let note = match self.seen_total {
            Some(total) if total > shown => format!("First {shown} of {total}, closest to use first. Narrow with the search box."),
            Some(total) => format!("{}, closest to use first.", format::count(total, "address", "addresses")),
            None => "Counting…".to_string(),
        };
        h_flex()
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .text_color(t.text_secondary)
            .child(div().flex_1().min_w_0().truncate().child(note))
            .child(Check::new("acc-bulk", "Include bulk addresses (dumps, lists)", self.show_bulk, cx.listener(|this, _, _, cx| this.toggle_bulk(cx))))
    }
}

impl Render for AccountsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let header = h_flex().pr(t.gutter).child(div().flex_1().child(self.header(cx)));
        if self.tab == Tab::AllTraces {
            return v_flex().size_full().gap(px(12.)).child(header).child(div().flex_1().min_h_0().size_full().child(self.raw.clone())).into_any_element();
        }
        let detail = self.detail.clone().map(|d| {
            let this = cx.entity().downgrade();
            let (jump_to, finding_to) = (this.clone(), this.clone());
            let on_jump = Rc::new(move |jump: Jump, _: &mut Window, cx: &mut gpui::App| {
                let _ = jump_to.update(cx, |_, cx| cx.emit(jump));
            });
            let on_finding = Rc::new(move |_id: i64, value: String, _: &mut Window, cx: &mut gpui::App| {
                let _ = finding_to.update(cx, |v, cx| v.show_finding(&value, cx));
            });
            AccountDetail::new(d, self.session.read(cx).snapshot().clone(), on_jump, on_finding, move |_, _, cx| {
                let _ = this.update(cx, |v, cx| {
                    v.detail = None;
                    cx.notify();
                });
            })
        });
        let stale = self.stale.then(|| {
            div()
                .text_size(t.size_body)
                .text_color(t.text_secondary)
                .child("These accounts were resolved by an older version and are not sorted by use yet. Press Rebuild.")
        });
        let table = if self.pick == Pick::Seen {
            v_flex().size_full().gap(px(8.)).child(self.seen_bar(cx)).child(div().flex_1().min_h_0().child(flat_table(&self.seen_table))).into_any_element()
        } else {
            flat_table(&self.used_table).into_any_element()
        };
        let list = div()
            .relative()
            .flex_1()
            .min_w_0()
            .h_full()
            .pl(px(12.))
            .pr(t.gutter)
            .child(table)
            .when(self.loading, |el| el.child(loading_edge("acc-loading")));
        v_flex()
            .size_full()
            .gap(px(12.))
            .child(header)
            .children(stale)
            .child(h_flex().flex_1().min_h_0().items_start().child(self.rail(cx)).child(list).when_some(detail, |el, d| el.child(d)))
            .into_any_element()
    }
}
