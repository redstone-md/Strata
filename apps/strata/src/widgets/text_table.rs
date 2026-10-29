use crate::theme::tokens;
use gpui::{App, Context, IntoElement, ParentElement, Pixels, SharedString, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, ColumnSort, TableDelegate, TableState};

/// How a [`TextTable`] column is set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    /// UI text.
    Text,
    /// Data value (path, key, address): data face.
    Data,
    /// Count or size: right-aligned.
    Number,
}

/// Table delegate over plain text rows — used wherever a view just lists strings
/// (correlation results, host facts). Columns sort by text, numerically when both cells parse.
pub struct TextTable {
    columns: Vec<(SharedString, Pixels, Cell)>,
    rows: Vec<Vec<SharedString>>,
    empty: SharedString,
}

impl TextTable {
    pub fn new(columns: Vec<(&'static str, f32, Cell)>, empty: &'static str) -> Self {
        Self {
            columns: columns.into_iter().map(|(n, w, c)| (n.into(), px(w), c)).collect(),
            rows: Vec::new(),
            empty: empty.into(),
        }
    }

    pub fn set_rows(&mut self, rows: Vec<Vec<SharedString>>) {
        self.rows = rows;
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// A row may carry one hidden cell after the visible columns: a key that identifies what
    /// the row shows (it moves with the row when the table is sorted).
    pub fn row_key(&self, row: usize) -> Option<SharedString> {
        self.rows.get(row).and_then(|r| r.get(self.columns.len())).cloned()
    }

    fn cell(&self, row: usize, col: usize) -> SharedString {
        self.rows.get(row).and_then(|r| r.get(col)).cloned().unwrap_or_default()
    }
}

fn sort_key(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.trim_end_matches('%').parse().ok()
}

/// Header cell shared by every table: 12px secondary text, right-aligned over numbers.
pub fn table_header(name: SharedString, right: bool) -> impl IntoElement {
    let t = tokens();
    let row = h_flex().size_full().text_size(t.size_small).text_color(t.text_secondary).child(name);
    if right { row.justify_end() } else { row }
}

/// Empty-table message shared by every table.
pub fn table_empty(text: SharedString) -> impl IntoElement {
    let t = tokens();
    h_flex().size_full().p_4().items_start().text_size(t.size_body).text_color(t.text_secondary).child(text)
}

impl TableDelegate for TextTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width, cell) = &self.columns[col_ix];
        let col = Column::new(name.clone(), name.clone()).width(*width).sortable();
        if *cell == Cell::Number { col.text_right() } else { col }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let (name, _, cell) = &self.columns[col_ix];
        table_header(name.clone(), *cell == Cell::Number)
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_empty(self.empty.clone())
    }

    fn perform_sort(&mut self, col_ix: usize, sort: ColumnSort, _: &mut Window, _: &mut Context<TableState<Self>>) {
        let cmp = |a: &Vec<SharedString>, b: &Vec<SharedString>| {
            let (x, y) = (a.get(col_ix).map(|s| s.as_ref()).unwrap_or(""), b.get(col_ix).map(|s| s.as_ref()).unwrap_or(""));
            match (sort_key(x), sort_key(y)) {
                (Some(p), Some(q)) => p.total_cmp(&q),
                _ => x.to_lowercase().cmp(&y.to_lowercase()),
            }
        };
        match sort {
            ColumnSort::Descending => self.rows.sort_by(|a, b| cmp(b, a)),
            _ => self.rows.sort_by(cmp),
        }
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let cell = div().w_full().text_size(t.size_body).text_color(t.text).truncate().child(self.cell(row_ix, col_ix));
        match self.columns[col_ix].2 {
            Cell::Text => cell,
            Cell::Data => cell.font_family(t.font_data),
            Cell::Number => cell.text_right(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.cell(row_ix, col_ix).to_string()
    }
}

/// The app's one table look: flat, 28px rows, no stripes, no outer border.
pub fn flat_table<D: TableDelegate>(state: &gpui::Entity<TableState<D>>) -> gpui_component::table::DataTable<D> {
    use gpui_component::Sizable as _;
    let h = tokens().row_height;
    gpui_component::table::DataTable::new(state)
        .stripe(false)
        .bordered(false)
        .with_size(gpui_component::Size::Size(h))
        .header_row_height(h)
}
