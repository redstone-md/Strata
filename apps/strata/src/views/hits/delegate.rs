//! The one table delegate behind every hit list (Wallets & Keys, Accounts).

use super::columns::{DiskLabels, HitColumn};
use crate::widgets::{table_empty, table_header};
use gpui::{App, Context, IntoElement, Window};
use gpui_component::table::{Column, ColumnSort, TableDelegate, TableState};
use std::sync::Arc;
use strata_workbench::{HitCategory, HitQuery, StoredHit, Workbench};

/// Rows fetched per page; more are loaded as the user scrolls.
const PAGE: usize = 2000;
/// Occurrences listed under "Found at" in the detail panel.
const MAX_PLACES: usize = 500;

pub struct HitTableDelegate {
    workbench: Arc<Workbench>,
    columns: Vec<HitColumn>,
    query: HitQuery,
    rows: Vec<StoredHit>,
    disks: DiskLabels,
    has_more: bool,
    sort: Option<(HitColumn, ColumnSort)>,
}

impl HitTableDelegate {
    pub fn new(workbench: Arc<Workbench>, columns: Vec<HitColumn>, query: HitQuery) -> Self {
        Self { workbench, columns, query: HitQuery { limit: PAGE, group_by_value: true, ..query }, rows: Vec::new(), disks: DiskLabels::new(), has_more: false, sort: None }
    }

    pub fn set_text(&mut self, text: &str) {
        self.query.text = Some(text.trim().to_string()).filter(|t| !t.is_empty());
    }

    pub fn set_categories(&mut self, categories: Vec<HitCategory>) {
        self.query.categories = categories;
    }

    pub fn set_workbench(&mut self, workbench: Arc<Workbench>) {
        self.workbench = workbench;
    }

    pub fn set_initial_sort(&mut self, column: HitColumn) {
        self.sort = Some((column, ColumnSort::Ascending));
    }

    /// Re-run the query from the first page.
    pub fn reload(&mut self, disks: DiskLabels) {
        self.disks = disks;
        self.query.offset = 0;
        self.rows = self.workbench.hits(&self.query).unwrap_or_default();
        self.has_more = self.rows.len() == PAGE;
        self.apply_sort();
    }

    pub fn row(&self, ix: usize) -> Option<&StoredHit> {
        self.rows.get(ix)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn has_more_rows(&self) -> bool {
        self.has_more
    }

    /// Every occurrence of a grouped value (capped), for the detail panel.
    pub fn places(&self, hit: &StoredHit) -> Vec<StoredHit> {
        if hit.occurrences <= 1 {
            return Vec::new();
        }
        let q = HitQuery {
            categories: vec![hit.hit.category],
            exact_value: Some(hit.hit.value.clone()),
            limit: MAX_PLACES,
            ..HitQuery::default()
        };
        self.workbench.hits(&q).unwrap_or_default()
    }

    pub fn disk_label(&self, hit: &StoredHit) -> String {
        HitColumn::Disk.text(hit, &self.disks)
    }

    fn apply_sort(&mut self) {
        let Some((col, sort)) = self.sort else { return };
        let disks = &self.disks;
        match sort {
            ColumnSort::Descending => self.rows.sort_by(|a, b| col.compare(b, a, disks)),
            ColumnSort::Ascending => self.rows.sort_by(|a, b| col.compare(a, b, disks)),
            ColumnSort::Default => {}
        }
    }
}

impl TableDelegate for HitTableDelegate {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        self.columns[col_ix].column()
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let col = self.columns[col_ix];
        table_header(col.column().name.clone(), col.numeric())
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let text = if self.query.text.is_some() { "Nothing matches the search." } else { "Nothing found yet. Analyse a disk to fill this list." };
        table_empty(text.into())
    }

    fn perform_sort(&mut self, col_ix: usize, sort: ColumnSort, _: &mut Window, _: &mut Context<TableState<Self>>) {
        self.sort = Some((self.columns[col_ix], sort));
        self.apply_sort();
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        match self.rows.get(row_ix) {
            Some(hit) => self.columns[col_ix].render(hit, &self.disks),
            None => gpui::Empty.into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.rows.get(row_ix).map(|h| self.columns[col_ix].text(h, &self.disks)).unwrap_or_default()
    }

    fn has_more(&self, _: &App) -> bool {
        self.has_more
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) {
        if !self.has_more {
            return;
        }
        self.query.offset = self.rows.len();
        let page = self.workbench.hits(&self.query).unwrap_or_default();
        self.has_more = page.len() == PAGE;
        self.rows.extend(page);
        self.apply_sort();
        cx.notify();
    }
}
