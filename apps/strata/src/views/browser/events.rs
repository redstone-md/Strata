//! Table of browser events for one segment (history, searches, downloads, logins and forms),
//! paged from the case. Every page, the first and the following ones, is read off the UI
//! thread; a page that lands after the list was refilled is dropped.

use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::collections::HashMap;
use std::sync::Arc;
use strata_workbench::{BrowserQuery, BrowserRow, BrowserSegment, EvidenceId, Workbench, site_key};

pub const PAGE: usize = 2000;

/// Column headers and widths per segment.
fn columns(segment: BrowserSegment) -> &'static [(&'static str, f32)] {
    match segment {
        BrowserSegment::History => &[("Time", 150.), ("URL", 440.), ("Title / detail", 300.), ("Browser", 220.), ("Disk", 110.), ("State", 110.)],
        BrowserSegment::Searches => &[("Time", 150.), ("Search", 380.), ("Where", 300.), ("Browser", 220.), ("Disk", 110.), ("State", 110.)],
        BrowserSegment::Downloads => &[("Time", 150.), ("File", 360.), ("From", 360.), ("Size", 90.), ("Browser", 220.), ("Disk", 110.), ("State", 110.)],
        BrowserSegment::Logins => &[("Time", 150.), ("What", 100.), ("Site", 220.), ("Field", 160.), ("Value", 240.), ("Browser", 220.), ("Disk", 110.)],
        BrowserSegment::Cookies => &[("Time", 150.), ("Host", 300.), ("Cookie", 300.), ("Browser", 220.), ("Disk", 110.)],
    }
}

pub struct EventsDelegate {
    workbench: Arc<Workbench>,
    query: BrowserQuery,
    rows: Vec<BrowserRow>,
    disks: HashMap<EvidenceId, String>,
    has_more: bool,
    /// The first page has arrived; until then the empty state says "Loading".
    loaded: bool,
    /// A following page is being read.
    fetching: bool,
    /// Bumped per refill so a late page of the previous list is dropped.
    epoch: u64,
}

impl EventsDelegate {
    pub fn new(workbench: Arc<Workbench>) -> Self {
        Self {
            workbench,
            query: BrowserQuery::default(),
            rows: Vec::new(),
            disks: HashMap::new(),
            has_more: false,
            loaded: false,
            fetching: false,
            epoch: 0,
        }
    }

    pub fn set_workbench(&mut self, workbench: Arc<Workbench>) {
        self.workbench = workbench;
    }

    /// A new list is being read: show "Loading" until it lands.
    pub fn begin(&mut self) {
        self.epoch += 1;
        self.loaded = false;
        self.fetching = false;
    }

    /// The first page of `query`.
    pub fn set_rows(&mut self, query: BrowserQuery, disks: HashMap<EvidenceId, String>, rows: Vec<BrowserRow>) {
        self.has_more = rows.len() == PAGE;
        self.query = query;
        self.disks = disks;
        self.rows = rows;
        self.loaded = true;
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn has_more_rows(&self) -> bool {
        self.has_more
    }

    fn disk(&self, id: EvidenceId) -> String {
        self.disks.get(&id).cloned().unwrap_or_else(|| id.to_string())
    }

    fn filtered(&self) -> bool {
        let f = &self.query.filter;
        f.text.is_some() || f.site.is_some() || f.crypto_only || f.profile.is_some()
    }

    /// Text of one cell; also what the table copies.
    fn text(&self, row: &BrowserRow, col: usize) -> String {
        let e = &row.event;
        match (self.query.segment, col) {
            (_, 0) => e.at().to_string(),
            (BrowserSegment::History | BrowserSegment::Searches, 1) => e.title().to_string(),
            (BrowserSegment::History, 2) => e.detail().to_string(),
            (BrowserSegment::Searches, 2) => match site_key(e.detail()) {
                host if !host.is_empty() && e.detail().contains("://") => host,
                _ => e.detail().to_string(),
            },
            (BrowserSegment::Downloads, 1) => e.title().to_string(),
            (BrowserSegment::Downloads, 2) => row.download_source().map(|d| d.url).unwrap_or_else(|| e.detail().to_string()),
            (BrowserSegment::Downloads, 3) => row.download_source().and_then(|d| d.bytes).map(crate::format::bytes).unwrap_or_default(),
            (BrowserSegment::Logins, 1..=4) => {
                let Some(c) = row.credential() else { return e.title().to_string() };
                match col {
                    1 => c.what.to_string(),
                    2 => c.site,
                    3 => c.field,
                    _ if c.value.is_empty() => e.detail().to_string(),
                    _ => c.value,
                }
            }
            (BrowserSegment::Cookies, 1) => e.title().to_string(),
            (BrowserSegment::Cookies, 2) => e.detail().to_string(),
            (segment, c) => match columns(segment).get(c).map(|(name, _)| *name) {
                Some("Browser") => row.profile().label(),
                Some("Disk") => self.disk(row.evidence),
                Some("State") => state_words(row).join(", "),
                _ => String::new(),
            },
        }
    }
}

/// `deleted`, `crypto`: what the State column marks.
fn state_words(row: &BrowserRow) -> Vec<&'static str> {
    let mut out = Vec::new();
    if row.deleted() {
        out.push("deleted");
    }
    if row.event.is_crypto() {
        out.push("crypto");
    }
    out
}

impl TableDelegate for EventsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        columns(self.query.segment).len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = columns(self.query.segment)[col_ix];
        let col = Column::new(name, name).width(px(width));
        if name == "Size" { col.text_right() } else { col }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let name = columns(self.query.segment)[col_ix].0;
        table_header(name.into(), name == "Size")
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let text = match (self.loaded, self.filtered()) {
            (false, _) => "Loading browser history…",
            (true, true) => "Nothing matches.",
            (true, false) => "Nothing here. Browser history appears after the artefacts step has run on a disk.",
        };
        table_empty(text.into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(row) = self.rows.get(row_ix) else { return gpui::Empty.into_any_element() };
        let name = columns(self.query.segment)[col_ix].0;
        let text = self.text(row, col_ix);
        match name {
            "State" => h_flex().gap(px(4.)).children(state_words(row).into_iter().map(Badge::outline)).into_any_element(),
            "Time" => mono().text_size(t.size_body).text_color(t.text_secondary).child(text).into_any_element(),
            "URL" | "File" | "From" | "Host" | "Value" => {
                let color = if row.event.is_crypto() { t.emphasis } else { t.text };
                mono().w_full().min_w_0().text_size(t.size_body).text_color(color).truncate().child(text).into_any_element()
            }
            "Size" => div().w_full().text_right().text_size(t.size_body).text_color(t.text).child(text).into_any_element(),
            "Browser" | "Disk" | "Where" | "What" | "Title / detail" | "Cookie" => {
                div().w_full().text_size(t.size_body).text_color(t.text_secondary).truncate().child(text).into_any_element()
            }
            _ => div().w_full().text_size(t.size_body).text_color(t.emphasis).truncate().child(text).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.rows.get(row_ix).map(|r| self.text(r, col_ix)).unwrap_or_default()
    }

    fn has_more(&self, _: &App) -> bool {
        self.has_more
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) {
        if !self.has_more || self.fetching {
            return;
        }
        self.fetching = true;
        let query = BrowserQuery { offset: self.rows.len(), ..self.query.clone() };
        let (wb, epoch) = (self.workbench.clone(), self.epoch);
        cx.spawn(async move |table, cx| {
            let page = cx.background_executor().spawn(async move { wb.browser_rows(&query).unwrap_or_default() }).await;
            let _ = table.update(cx, |t, cx| {
                let d = t.delegate_mut();
                if d.epoch != epoch {
                    return;
                }
                d.fetching = false;
                d.has_more = page.len() == PAGE;
                d.rows.extend(page);
                cx.notify();
            });
        })
        .detach();
    }
}
