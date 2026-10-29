//! Table of hosts: sites visited, or sites that set cookies. Crypto-related hosts (a
//! catalogued exchange, wallet, faucet, pool or forum, or crypto-tagged visits) come first and
//! are marked. Selecting a row lists the site's history.

use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, prelude::FluentBuilder as _, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::collections::HashMap;
use strata_workbench::{BrowserSpan, CookieSite, EvidenceId, Service, SiteSummary};

const SITES: [(&str, f32); 7] = [("Site", 300.), ("Service", 240.), ("Visits", 80.), ("Deleted", 80.), ("First", 100.), ("Last", 100.), ("Disks", 200.)];
const COOKIES: [(&str, f32); 7] =
    [("Site", 300.), ("Service", 240.), ("Events", 80.), ("Cookie names", 320.), ("First", 100.), ("Last", 100.), ("Disks", 200.)];

/// What the table lists.
pub enum Hosts {
    Sites(Vec<SiteSummary>),
    Cookies(Vec<CookieSite>),
}

/// The parts of a host row both kinds share.
struct HostRow<'a> {
    host: &'a str,
    service: Option<Service>,
    crypto: bool,
    count: u64,
    span: BrowserSpan,
    disks: &'a [EvidenceId],
}

pub struct HostsDelegate {
    hosts: Hosts,
    disks: HashMap<EvidenceId, String>,
    loaded: bool,
    filtered: bool,
}

fn day(t: strata_workbench::Timestamp) -> String {
    t.to_string().chars().take(10).collect()
}

impl HostsDelegate {
    pub fn new() -> Self {
        Self { hosts: Hosts::Sites(Vec::new()), disks: HashMap::new(), loaded: false, filtered: false }
    }

    pub fn begin(&mut self) {
        self.loaded = false;
    }

    pub fn set_hosts(&mut self, hosts: Hosts, disks: HashMap<EvidenceId, String>, filtered: bool) {
        self.hosts = hosts;
        self.disks = disks;
        self.filtered = filtered;
        self.loaded = true;
    }

    pub fn len(&self) -> usize {
        match &self.hosts {
            Hosts::Sites(s) => s.len(),
            Hosts::Cookies(c) => c.len(),
        }
    }

    pub fn crypto(&self) -> usize {
        (0..self.len()).filter(|&i| self.row(i).is_some_and(|r| r.crypto)).count()
    }

    pub fn host(&self, ix: usize) -> Option<String> {
        self.row(ix).map(|r| r.host.to_string())
    }

    /// Counts: visits / events, and deleted visits.
    fn numeric(&self, col: usize) -> bool {
        col == 2 || (col == 3 && matches!(self.hosts, Hosts::Sites(_)))
    }

    fn columns(&self) -> &'static [(&'static str, f32)] {
        match self.hosts {
            Hosts::Sites(_) => &SITES,
            Hosts::Cookies(_) => &COOKIES,
        }
    }

    fn row(&self, ix: usize) -> Option<HostRow<'_>> {
        Some(match &self.hosts {
            Hosts::Sites(s) => {
                let s = s.get(ix)?;
                HostRow { host: &s.host, service: s.service, crypto: s.is_crypto(), count: s.visits, span: s.span, disks: &s.disks }
            }
            Hosts::Cookies(c) => {
                let c = c.get(ix)?;
                HostRow { host: &c.host, service: c.service, crypto: c.is_crypto(), count: c.events, span: c.span, disks: &c.disks }
            }
        })
    }

    fn text(&self, ix: usize, col: usize) -> String {
        let Some(r) = self.row(ix) else { return String::new() };
        match col {
            0 => r.host.to_string(),
            1 => r.service.map(|s| format!("{} · {}", s.name, s.kind.label())).unwrap_or_default(),
            2 => r.count.to_string(),
            3 => match &self.hosts {
                Hosts::Sites(s) => s.get(ix).map(|s| s.deleted).filter(|n| *n > 0).map(|n| n.to_string()).unwrap_or_default(),
                Hosts::Cookies(c) => c.get(ix).map(|c| c.names.join(", ")).unwrap_or_default(),
            },
            4 => day(r.span.first),
            5 => day(r.span.last),
            _ => r.disks.iter().map(|d| self.disks.get(d).cloned().unwrap_or_else(|| d.to_string())).collect::<Vec<_>>().join(", "),
        }
    }
}

impl TableDelegate for HostsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns().len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = self.columns()[col_ix];
        let col = Column::new(name, name).width(px(width));
        if self.numeric(col_ix) { col.text_right() } else { col }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_header(self.columns()[col_ix].0.into(), self.numeric(col_ix))
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let text = match (self.loaded, self.filtered) {
            (false, _) => "Loading sites…",
            (true, true) => "No site matches.",
            (true, false) => "No sites yet. They appear after the artefacts step has run on a disk.",
        };
        table_empty(text.into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(crypto) = self.row(row_ix).map(|r| r.crypto) else { return gpui::Empty.into_any_element() };
        let text = self.text(row_ix, col_ix);
        let right = self.numeric(col_ix);
        match col_ix {
            0 => mono()
                .w_full()
                .min_w_0()
                .text_size(t.size_body)
                .text_color(if crypto { t.emphasis } else { t.text })
                .when(crypto, |el| el.font_weight(t.semibold))
                .truncate()
                .child(text)
                .into_any_element(),
            1 if crypto => h_flex().gap(px(6.)).min_w_0().child(Badge::outline("crypto")).child(div().min_w_0().truncate().text_size(t.size_body).text_color(t.text).child(text)).into_any_element(),
            _ if right => div().w_full().text_right().text_size(t.size_body).text_color(t.text).child(text).into_any_element(),
            4 | 5 => mono().text_size(t.size_body).text_color(t.text_secondary).child(text).into_any_element(),
            _ => div().w_full().text_size(t.size_body).text_color(t.text_secondary).truncate().child(text).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.text(row_ix, col_ix)
    }
}
