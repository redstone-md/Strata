//! Browser: the history the artefact parsers read from Chromium browsers, Firefox, Opera and
//! Internet Explorer, as its own screen. Profiles per disk on top; below them the history,
//! searches, downloads, saved logins and form values, cookies by site, and visited sites with
//! crypto-related services marked. The command-bar search and the case's period narrow
//! everything; a profile or a site narrows the lists.

mod events;
mod hosts;
mod profiles;

use crate::format;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{TextButton, TextTable, flat_table, loading_edge};
use events::{EventsDelegate, PAGE};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, Styled, Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use hosts::{Hosts, HostsDelegate};
use std::collections::HashMap;
use strata_workbench::{BrowserFilter, BrowserQuery, BrowserSegment, EvidenceId, Period, ProfileSummary};

/// The lists of the screen, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    List(BrowserSegment),
    Sites,
}

impl Tab {
    const ALL: [Tab; 6] = [
        Tab::List(BrowserSegment::History),
        Tab::List(BrowserSegment::Searches),
        Tab::List(BrowserSegment::Downloads),
        Tab::List(BrowserSegment::Logins),
        Tab::List(BrowserSegment::Cookies),
        Tab::Sites,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::List(s) => s.label(),
            Tab::Sites => "Sites",
        }
    }

    /// Cookies are listed by the site that set them.
    fn by_host(self) -> bool {
        matches!(self, Tab::Sites | Tab::List(BrowserSegment::Cookies))
    }

    fn nouns(self) -> (&'static str, &'static str) {
        match self {
            Tab::List(BrowserSegment::History) => ("visit", "visits"),
            Tab::List(BrowserSegment::Searches) => ("search", "searches"),
            Tab::List(BrowserSegment::Downloads) => ("download", "downloads"),
            Tab::List(BrowserSegment::Logins) => ("login or form value", "logins and form values"),
            Tab::List(BrowserSegment::Cookies) => ("site setting cookies", "sites setting cookies"),
            Tab::Sites => ("site", "sites"),
        }
    }
}

pub struct BrowserView {
    session: Entity<Session>,
    events: Entity<TableState<EventsDelegate>>,
    hosts: Entity<TableState<HostsDelegate>>,
    profile_table: Entity<TableState<TextTable>>,
    tab: Tab,
    /// Search text, crypto-only and the selected profile and site; the period is added per load.
    filter: BrowserFilter,
    profiles: Vec<ProfileSummary>,
    /// Rows of the current event list in the case.
    total: u64,
    generation: u64,
    was_active: bool,
    period: Period,
    /// Bumped per load; a slower earlier load that lands late is dropped.
    list_loads: u64,
    overview_loads: u64,
    loading: bool,
    _subscriptions: Vec<Subscription>,
}

impl BrowserView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let workbench = session.read(cx).workbench().clone();
        let events = cx.new(|cx| TableState::new(EventsDelegate::new(workbench), window, cx).col_movable(false));
        let hosts = cx.new(|cx| TableState::new(HostsDelegate::new(), window, cx).col_movable(false));
        let profile_table = cx.new(|cx| TableState::new(profiles::table(), window, cx).col_movable(false));
        let subscriptions = vec![
            cx.subscribe_in(&hosts, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event
                    && let Some(host) = table.read(cx).delegate().host(*ix)
                {
                    this.show_site(Some(host), cx);
                }
            }),
            cx.subscribe_in(&profile_table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event
                    && let Some(i) = table.read(cx).delegate().row_key(*ix).and_then(|k| k.parse::<usize>().ok())
                {
                    let key = this.profiles.get(i).map(|p| p.key.clone());
                    this.show_profile(if this.filter.profile == key { None } else { key }, cx);
                }
            }),
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            events,
            hosts,
            profile_table,
            tab: Tab::List(BrowserSegment::History),
            filter: BrowserFilter::default(),
            profiles: Vec::new(),
            total: 0,
            generation,
            was_active: false,
            period: Period::ALL,
            list_loads: 0,
            overview_loads: 0,
            loading: false,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            let wb = session.workbench().clone();
            self.filter.profile = None;
            self.events.update(cx, |t, _| t.delegate_mut().set_workbench(wb));
            self.reload(cx);
        } else if session.period() != self.period || self.was_active && !active {
            self.reload(cx);
        }
        self.was_active = active;
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        let text = Some(text.trim().to_string()).filter(|t| !t.is_empty());
        if text != self.filter.text {
            self.filter.text = text;
            self.reload(cx);
        }
    }

    fn show_tab(&mut self, tab: Tab, cx: &mut Context<Self>) {
        self.tab = tab;
        self.reload_list(cx);
    }

    /// List the history of one site (from the site and cookie tables), or of all sites.
    fn show_site(&mut self, site: Option<String>, cx: &mut Context<Self>) {
        self.filter.site = site;
        if self.filter.site.is_some() && self.tab.by_host() {
            self.tab = Tab::List(BrowserSegment::History);
        }
        self.reload_list(cx);
    }

    fn show_profile(&mut self, profile: Option<strata_workbench::ProfileKey>, cx: &mut Context<Self>) {
        self.filter.profile = profile;
        self.reload_list(cx);
    }

    fn toggle_crypto(&mut self, cx: &mut Context<Self>) {
        self.filter.crypto_only = !self.filter.crypto_only;
        self.reload(cx);
    }

    fn disks(&self, cx: &Context<Self>) -> HashMap<EvidenceId, String> {
        self.session.read(cx).snapshot().disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect()
    }

    /// Profiles and sites, then the current list.
    fn reload(&mut self, cx: &mut Context<Self>) {
        self.period = self.session.read(cx).period();
        // The site table is the overview's; its list load reads it.
        if self.tab != Tab::Sites {
            self.reload_overview(cx);
        }
        self.reload_list(cx);
    }

    /// Profiles and sites for the search, crypto filter and period (not the profile or site
    /// picked, so the strip keeps every profile in reach).
    fn reload_overview(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        let filter = BrowserFilter { profile: None, site: None, ..self.filter.clone() }.within(self.period);
        let disks = self.disks(cx);
        self.overview_loads += 1;
        let ticket = self.overview_loads;
        cx.spawn(async move |this, cx| {
            let overview = cx.background_executor().spawn(async move { wb.browser_overview(&filter).unwrap_or_default() }).await;
            let _ = this.update(cx, |v, cx| {
                if v.overview_loads != ticket {
                    return;
                }
                let rows = profiles::rows(&overview.profiles, &disks);
                v.profiles = overview.profiles;
                v.profile_table.update(cx, |t, cx| {
                    t.delegate_mut().set_rows(rows);
                    t.refresh(cx);
                    cx.notify();
                });
                if v.tab == Tab::Sites {
                    let filtered = v.filter.text.is_some() || v.filter.crypto_only;
                    v.hosts.update(cx, |t, cx| {
                        t.delegate_mut().set_hosts(Hosts::Sites(overview.sites), disks, filtered);
                        t.refresh(cx);
                        cx.notify();
                    });
                    v.loading = false;
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// The current tab's rows (first page and total, or the host table) off the UI thread.
    fn reload_list(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        let filter = self.filter.clone().within(self.period);
        let disks = self.disks(cx);
        self.list_loads += 1;
        let ticket = self.list_loads;
        self.loading = true;
        match self.tab {
            // The overview load fills the site table.
            Tab::Sites => {
                self.hosts.update(cx, |t, cx| {
                    t.delegate_mut().begin();
                    cx.notify();
                });
                self.reload_overview(cx);
            }
            Tab::List(BrowserSegment::Cookies) => {
                self.hosts.update(cx, |t, _| t.delegate_mut().begin());
                let filtered = filter.text.is_some() || filter.crypto_only || filter.profile.is_some();
                cx.spawn(async move |this, cx| {
                    let sites = cx.background_executor().spawn(async move { wb.browser_cookie_sites(&filter).unwrap_or_default() }).await;
                    let _ = this.update(cx, |v, cx| {
                        if v.list_loads != ticket {
                            return;
                        }
                        v.loading = false;
                        v.hosts.update(cx, |t, cx| {
                            t.delegate_mut().set_hosts(Hosts::Cookies(sites), disks, filtered);
                            t.refresh(cx);
                            cx.notify();
                        });
                        cx.notify();
                    });
                })
                .detach();
            }
            Tab::List(segment) => {
                self.events.update(cx, |t, _| t.delegate_mut().begin());
                let query = BrowserQuery { filter, segment, limit: PAGE, offset: 0 };
                cx.spawn(async move |this, cx| {
                    let q = query.clone();
                    let (rows, total) =
                        cx.background_executor().spawn(async move { (wb.browser_rows(&q).unwrap_or_default(), wb.browser_count(&q).unwrap_or_default()) }).await;
                    let _ = this.update(cx, |v, cx| {
                        if v.list_loads != ticket {
                            return;
                        }
                        v.loading = false;
                        v.total = total;
                        v.events.update(cx, |t, cx| {
                            t.delegate_mut().set_rows(query, disks, rows);
                            t.refresh(cx);
                            cx.notify();
                        });
                        cx.notify();
                    });
                })
                .detach();
            }
        }
        cx.notify();
    }

    fn count(&self, cx: &Context<Self>) -> String {
        let (one, many) = self.tab.nouns();
        if self.tab.by_host() {
            let hosts = self.hosts.read(cx).delegate();
            let crypto = hosts.crypto();
            let n = format::count(hosts.len() as u64, one, many);
            return if crypto > 0 { format!("{n}, {crypto} crypto-related") } else { n };
        }
        let d = self.events.read(cx).delegate();
        if d.has_more_rows() { format!("first {} of {} {many}, scroll for more", d.len(), self.total) } else { format::count(d.len() as u64, one, many) }
    }

    /// `matching “x”  Clear search`, the picked profile and site, each with its way back.
    fn narrowing(&self, cx: &mut Context<Self>) -> Vec<gpui::AnyElement> {
        let t = tokens();
        let chip = |text: String, button: TextButton| h_flex().gap(px(8.)).child(div().text_color(t.text).child(text)).child(button).into_any_element();
        let mut out = Vec::new();
        if let Some(text) = &self.filter.text {
            let clear = TextButton::new("clear-search", "Clear search")
                .on_click(|_, window, cx| window.dispatch_action(Box::new(crate::shell::ClearSearch), cx));
            out.push(chip(format!("matching “{text}”"), clear));
        }
        if let Some(p) = &self.filter.profile {
            let all = TextButton::new("all-profiles", "All profiles").on_click(cx.listener(|this, _, _, cx| this.show_profile(None, cx)));
            out.push(chip(p.label(), all));
        }
        if let Some(site) = &self.filter.site {
            let all = TextButton::new("all-sites", "All sites").on_click(cx.listener(|this, _, _, cx| this.show_site(None, cx)));
            out.push(chip(format!("site {site}"), all));
        }
        out
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let crypto = TextButton::new("browser-crypto", "Crypto-related only").on_click(cx.listener(|this, _, _, cx| this.toggle_crypto(cx)));
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Browser"))
            .child(div().text_color(t.text_secondary).child(self.count(cx)))
            .children(self.narrowing(cx))
            .child(div().flex_1())
            .child(if self.filter.crypto_only { crypto.strong() } else { crypto })
    }

    fn tabs(&self, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex().gap(px(6.)).children(Tab::ALL.into_iter().enumerate().map(|(i, tab)| {
            let button = TextButton::new(("browser-tab", i), tab.label()).on_click(cx.listener(move |this, _, _, cx| this.show_tab(tab, cx)));
            if self.tab == tab { button.strong() } else { button }
        }))
    }
}

impl Render for BrowserView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shown = self.profiles.len().min(profiles::SHOWN);
        let strip_height = t.row_height * (shown as f32 + 1.) + px(2.);
        let list = if self.tab.by_host() { flat_table(&self.hosts).into_any_element() } else { flat_table(&self.events).into_any_element() };
        v_flex()
            .size_full()
            .pr(t.gutter)
            .gap(px(12.))
            .child(self.header(cx))
            .when(shown > 0, |el| el.child(div().h(strip_height).flex_shrink_0().border_b_1().border_color(t.rule).child(flat_table(&self.profile_table))))
            .child(self.tabs(cx))
            .child(div().flex_1().min_h_0().size_full().relative().child(list).when(self.loading, |el| el.child(loading_edge("browser-loading"))))
    }
}
