//! Table of content-search matches, paged from the case: where each one is, which file it
//! belongs to, and the bytes around it with the match set in white.

use crate::format;
use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::sync::Arc;
use strata_workbench::{SearchResultRow, Snippet, Workbench};

const PAGE: usize = 2000;
const COLUMNS: [(&str, f32); 5] = [("Location", 140.), ("File", 300.), ("Offset", 120.), ("Encoding", 90.), ("Context", 560.)];

pub struct ResultsDelegate {
    workbench: Arc<Workbench>,
    search: Option<i64>,
    rows: Vec<SearchResultRow>,
    has_more: bool,
    /// Show the context as hex bytes instead of text.
    pub hex: bool,
    empty: &'static str,
}

/// `(before, match, after)` of a row's context bytes, as hex.
fn hex_parts(r: &SearchResultRow) -> (String, String, String) {
    let at = (r.offset - r.context_start) as usize;
    let end = (at + r.len as usize).min(r.context.len());
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X} ")).collect::<String>();
    let ctx = &r.context;
    // Eight bytes either side keep the cell readable.
    (hex(ctx.get(at.saturating_sub(8)..at).unwrap_or_default()), hex(ctx.get(at..end).unwrap_or_default()), hex(ctx.get(end..(end + 8).min(ctx.len())).unwrap_or_default()))
}

/// Long runs of placeholder dots (binary bytes) shortened to three, so text stays in view.
fn squeeze(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = 0;
    for c in s.chars() {
        run = if c == '·' { run + 1 } else { 0 };
        if run <= 3 {
            out.push(c);
        }
    }
    out
}

/// Badge and words for a stored location.
pub fn location_badge(location: &str) -> Badge {
    Badge::outline(location.to_string())
}

impl ResultsDelegate {
    pub fn new(workbench: Arc<Workbench>) -> Self {
        Self { workbench, search: None, rows: Vec::new(), has_more: false, hex: false, empty: "Run a search to list matches here." }
    }

    pub fn set_workbench(&mut self, workbench: Arc<Workbench>) {
        self.workbench = workbench;
        self.search = None;
        self.rows.clear();
    }

    pub fn show(&mut self, search: Option<i64>) {
        self.search = search;
        self.reload();
    }

    pub fn reload(&mut self) {
        self.rows = self.search.map(|s| self.workbench.search_results(s, 0, PAGE).unwrap_or_default()).unwrap_or_default();
        self.has_more = self.rows.len() == PAGE;
        self.empty = if self.search.is_some() { "No matches yet." } else { "Run a search to list matches here." };
    }

    pub fn row(&self, ix: usize) -> Option<&SearchResultRow> {
        self.rows.get(ix)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn has_more_rows(&self) -> bool {
        self.has_more
    }
}

impl TableDelegate for ResultsDelegate {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = COLUMNS[col_ix];
        let col = Column::new(name, name).width(px(width));
        if col_ix == 2 { col.text_right() } else { col }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_header(COLUMNS[col_ix].0.into(), col_ix == 2)
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_empty(self.empty.into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(r) = self.rows.get(row_ix) else { return gpui::Empty.into_any_element() };
        match col_ix {
            0 => h_flex().child(location_badge(&r.location)).into_any_element(),
            1 => match &r.file_path {
                Some(p) => mono().w_full().text_size(t.size_body).text_color(t.text).truncate().child(p.clone()).into_any_element(),
                None => div().text_size(t.size_body).text_color(t.text_secondary).child("free space").into_any_element(),
            },
            2 => mono().w_full().text_right().text_size(t.size_body).text_color(t.text_secondary).child(format::hex_offset(r.offset)).into_any_element(),
            3 => div().text_size(t.size_body).text_color(t.text_secondary).child(r.encoding.clone()).into_any_element(),
            _ => {
                let (before, matched, after) = if self.hex {
                    hex_parts(r)
                } else {
                    let (b, m, a) = Snippet::split(&r.preview, r.match_from, r.match_to);
                    (squeeze(&b), m, squeeze(&a))
                };
                // Keep the match in view: show only the end of the leading context.
                let before: String = before.chars().rev().take(if self.hex { 24 } else { 40 }).collect::<Vec<_>>().into_iter().rev().collect();
                h_flex()
                    .w_full()
                    .min_w_0()
                    .overflow_hidden()
                    .font_family(t.font_data)
                    .text_size(t.size_body)
                    .child(div().flex_shrink_0().text_color(t.text_secondary).child(before))
                    .child(div().flex_shrink_0().text_color(t.emphasis).font_weight(t.semibold).child(matched))
                    .child(div().min_w_0().text_color(t.text_secondary).truncate().child(after))
                    .into_any_element()
            }
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        let Some(r) = self.rows.get(row_ix) else { return String::new() };
        match col_ix {
            0 => r.location.clone(),
            1 => r.file_path.clone().unwrap_or_else(|| "free space".into()),
            2 => format::hex_offset(r.offset),
            3 => r.encoding.clone(),
            _ => r.preview.clone(),
        }
    }

    fn has_more(&self, _: &App) -> bool {
        self.has_more
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) {
        let Some(search) = self.search.filter(|_| self.has_more) else { return };
        let page = self.workbench.search_results(search, self.rows.len(), PAGE).unwrap_or_default();
        self.has_more = page.len() == PAGE;
        self.rows.extend(page);
        cx.notify();
    }
}
