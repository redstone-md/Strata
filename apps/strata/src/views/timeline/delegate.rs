//! Table of timeline events, paged from the case like the hit tables.

use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::collections::HashMap;
use std::sync::Arc;
use strata_workbench::{EventQuery, EvidenceId, TimelineEvent, Workbench};

const PAGE: usize = 2000;
const COLUMNS: [(&str, f32); 5] = [("Time", 170.), ("Kind", 150.), ("Event", 420.), ("Source", 380.), ("Disk", 110.)];

/// `UrlVisited` → `URL visited`.
pub fn kind_label(debug: &str) -> String {
    let mut words = String::new();
    for (i, ch) in debug.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            words.push(' ');
        }
        words.push(if i == 0 { ch } else { ch.to_ascii_lowercase() });
    }
    words.replace("Url", "URL").replace("Usb", "USB").replace("Mft", "MFT")
}

pub struct TimelineDelegate {
    workbench: Arc<Workbench>,
    query: EventQuery,
    rows: Vec<(EvidenceId, TimelineEvent)>,
    disks: HashMap<EvidenceId, String>,
    has_more: bool,
}

impl TimelineDelegate {
    pub fn new(workbench: Arc<Workbench>) -> Self {
        let query = EventQuery { skip_filesystem: true, limit: PAGE, ..EventQuery::default() };
        Self { workbench, query, rows: Vec::new(), disks: HashMap::new(), has_more: false }
    }

    pub fn query_mut(&mut self) -> &mut EventQuery {
        &mut self.query
    }

    pub fn query(&self) -> &EventQuery {
        &self.query
    }

    pub fn set_workbench(&mut self, workbench: Arc<Workbench>) {
        self.workbench = workbench;
    }

    /// The query for the first page, to run off the UI thread.
    pub fn first_page(&self) -> EventQuery {
        EventQuery { offset: 0, ..self.query.clone() }
    }

    pub fn set_rows(&mut self, disks: HashMap<EvidenceId, String>, rows: Vec<(EvidenceId, TimelineEvent)>) {
        self.disks = disks;
        self.query.offset = 0;
        self.has_more = rows.len() == PAGE;
        self.rows = rows;
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn has_more_rows(&self) -> bool {
        self.has_more
    }
}

impl TableDelegate for TimelineDelegate {
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
        table_empty("No events. Events appear after the artefacts job has run on a disk.".into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some((disk, e)) = self.rows.get(row_ix) else { return gpui::Empty.into_any_element() };
        let text = |s: String, color| div().w_full().text_size(t.size_body).text_color(color).truncate().child(s);
        match col_ix {
            0 => mono().text_size(t.size_body).text_color(t.text_secondary).child(e.at().to_string()).into_any_element(),
            1 => text(kind_label(&format!("{:?}", e.kind())), t.text_secondary).into_any_element(),
            2 => text(e.title().to_string(), if e.is_crypto() { t.emphasis } else { t.text }).into_any_element(),
            3 => h_flex()
                .gap_2()
                .min_w_0()
                .children(e.source().deleted.then(|| Badge::outline("deleted")))
                .child(mono().min_w_0().text_size(t.size_body).text_color(t.text).truncate().child(e.source().path.clone()))
                .into_any_element(),
            _ => text(self.disks.get(disk).cloned().unwrap_or_else(|| disk.to_string()), t.text_secondary).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        let Some((_, e)) = self.rows.get(row_ix) else { return String::new() };
        match col_ix {
            0 => e.at().to_string(),
            1 => kind_label(&format!("{:?}", e.kind())),
            2 => e.title().to_string(),
            3 => e.source().path.clone(),
            _ => String::new(),
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
        let page = self.workbench.events(&self.query).unwrap_or_default();
        self.has_more = page.len() == PAGE;
        self.rows.extend(page);
        cx.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::kind_label;

    #[test]
    fn labels_kinds_in_sentence_case() {
        assert_eq!(kind_label("UrlVisited"), "URL visited");
        assert_eq!(kind_label("UsbDevice"), "USB device");
        assert_eq!(kind_label("Login"), "Login");
    }
}
