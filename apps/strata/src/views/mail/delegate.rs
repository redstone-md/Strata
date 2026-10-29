//! Table of recovered messages, paged from the case like the timeline.

use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::collections::HashMap;
use std::sync::Arc;
use strata_workbench::{EvidenceId, MessageQuery, MessageRow, MessageState, Period, Workbench};

const PAGE: usize = 2000;
const COLUMNS: [(&str, f32); 7] =
    [("Date", 150.), ("From", 230.), ("To", 230.), ("Subject", 340.), ("Disk", 100.), ("State", 80.), ("Source", 340.)];

pub struct MailDelegate {
    workbench: Arc<Workbench>,
    query: MessageQuery,
    rows: Vec<MessageRow>,
    disks: HashMap<EvidenceId, String>,
    has_more: bool,
    /// The first page has arrived; until then the empty state says "Loading".
    loaded: bool,
    /// The case's period of interest.
    period: Period,
}

impl MailDelegate {
    pub fn new(workbench: Arc<Workbench>) -> Self {
        let query = MessageQuery { limit: PAGE, ..MessageQuery::default() };
        Self { workbench, query, rows: Vec::new(), disks: HashMap::new(), has_more: false, loaded: false, period: Period::ALL }
    }

    pub fn query_mut(&mut self) -> &mut MessageQuery {
        &mut self.query
    }

    /// The state filter (live, deleted, carved), `None` for all.
    pub fn state(&self) -> Option<MessageState> {
        self.query.state
    }

    pub fn set_workbench(&mut self, workbench: Arc<Workbench>) {
        self.workbench = workbench;
    }

    pub fn set_period(&mut self, period: Period) {
        self.period = period;
    }

    /// The query as run: the list's filters inside the case's period.
    fn effective(&self) -> MessageQuery {
        MessageQuery { from: self.period.later_start(self.query.from), to: self.period.earlier_end(self.query.to), ..self.query.clone() }
    }

    /// The query for the first page, to run off the UI thread.
    pub fn first_page(&self) -> MessageQuery {
        MessageQuery { offset: 0, ..self.effective() }
    }

    pub fn set_rows(&mut self, disks: HashMap<EvidenceId, String>, rows: Vec<MessageRow>) {
        self.disks = disks;
        self.query.offset = 0;
        self.has_more = rows.len() == PAGE;
        self.rows = rows;
        self.loaded = true;
    }

    pub fn row(&self, ix: usize) -> Option<&MessageRow> {
        self.rows.get(ix)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn has_more_rows(&self) -> bool {
        self.has_more
    }

    pub fn disk_label(&self, id: EvidenceId) -> String {
        self.disks.get(&id).cloned().unwrap_or_else(|| id.to_string())
    }

    fn filtered(&self) -> bool {
        self.query.text.is_some() || self.query.address.is_some()
    }
}

/// `2011-05-14 17:36` or `undated`.
pub fn date(row: &MessageRow) -> String {
    row.at.map_or_else(|| "undated".into(), |t| t.to_string().chars().take(16).collect())
}

/// Where the message is: its file (with the folder for mailboxes) or free space.
pub fn source(row: &MessageRow) -> String {
    row.location.path.clone().unwrap_or_else(|| format!("free space 0x{:X}", row.location.offset))
}

impl TableDelegate for MailDelegate {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = COLUMNS[col_ix];
        Column::new(name, name).width(px(width))
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_header(COLUMNS[col_ix].0.into(), false)
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let text = match (self.loaded, self.filtered()) {
            (false, _) => "Loading messages…",
            (true, true) => "No messages match.",
            (true, false) => "No messages. Messages appear after the mail job has run on a disk.",
        };
        table_empty(text.into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(m) = self.rows.get(row_ix) else { return gpui::Empty.into_any_element() };
        let text = |s: String, color| div().w_full().text_size(t.size_body).text_color(color).truncate().child(s);
        match col_ix {
            0 => mono().text_size(t.size_body).text_color(t.text_secondary).child(date(m)).into_any_element(),
            1 => text(m.from.clone(), t.text).into_any_element(),
            2 => text(m.to.clone(), t.text_secondary).into_any_element(),
            3 => h_flex()
                .gap_2()
                .min_w_0()
                .child(text(if m.subject.is_empty() { "(no subject)".into() } else { m.subject.clone() }, t.emphasis))
                .children((m.attachments > 0).then(|| Badge::outline(format!("{} att.", m.attachments))))
                .into_any_element(),
            4 => text(self.disk_label(m.evidence), t.text_secondary).into_any_element(),
            5 => match m.location.state {
                MessageState::Live => text("live".into(), t.text_secondary).into_any_element(),
                state => h_flex().child(Badge::outline(state.name())).into_any_element(),
            },
            _ => mono().min_w_0().text_size(t.size_body).text_color(t.text).truncate().child(source(m)).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        let Some(m) = self.rows.get(row_ix) else { return String::new() };
        match col_ix {
            0 => date(m),
            1 => m.from.clone(),
            2 => m.to.clone(),
            3 => m.subject.clone(),
            4 => self.disk_label(m.evidence),
            5 => m.location.state.name().to_string(),
            _ => source(m),
        }
    }

    fn has_more(&self, _: &App) -> bool {
        self.has_more
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) {
        if !self.has_more {
            return;
        }
        self.query.offset = self.rows.len();
        let page = self.workbench.messages(&self.effective()).unwrap_or_default();
        self.has_more = page.len() == PAGE;
        self.rows.extend(page);
        cx.notify();
    }
}
