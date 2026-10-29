use crate::theme::tokens;
use gpui::{App, Context, IntoElement, ParentElement, Pixels, SharedString, Styled, Window, div};
use gpui_component::table::{Column, ColumnSort, TableDelegate, TableState};

/// Table delegate over plain text rows — used wherever a view just lists strings
/// (correlation results, volumes). Columns sort by text, numerically when both cells parse.
pub struct TextTable {
    columns: Vec<(SharedString, Pixels)>,
    rows: Vec<Vec<SharedString>>,
}

impl TextTable {
    pub fn new(columns: Vec<(&'static str, f32)>) -> Self {
        Self { columns: columns.into_iter().map(|(n, w)| (n.into(), gpui::px(w))).collect(), rows: Vec::new() }
    }

    pub fn set_rows(&mut self, rows: Vec<Vec<SharedString>>) {
        self.rows = rows;
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    fn cell(&self, row: usize, col: usize) -> SharedString {
        self.rows.get(row).and_then(|r| r.get(col)).cloned().unwrap_or_default()
    }
}

fn sort_key(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.trim_end_matches('%').parse().ok()
}

impl TableDelegate for TextTable {
    fn columns_count(&self, _: &App) -> usize {
        self.columns.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = &self.columns[col_ix];
        Column::new(name.clone(), name.clone()).width(*width).sortable()
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
        div().text_sm().text_color(tokens().text).truncate().child(self.cell(row_ix, col_ix))
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.cell(row_ix, col_ix).to_string()
    }
}
