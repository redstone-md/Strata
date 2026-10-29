//! Table of file entries whose name matched, deleted and orphaned ones included.

use crate::format;
use crate::theme::tokens;
use crate::widgets::{Badge, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, TableDelegate, TableState};
use std::collections::HashMap;
use strata_workbench::{EvidenceId, FileRow, Timestamp};

const COLUMNS: [(&str, f32); 6] = [("State", 90.), ("Name", 260.), ("Path", 420.), ("Size", 90.), ("Modified", 160.), ("Disk", 120.)];

/// Badge for a stored entry state, `None` for live entries.
pub fn state_badge(state: &str) -> Option<Badge> {
    match state {
        "Deleted" => Some(Badge::outline("deleted")),
        "Orphan" => Some(Badge::outline("orphan")),
        _ => None,
    }
}

#[derive(Default)]
pub struct NamesDelegate {
    rows: Vec<FileRow>,
    disks: HashMap<EvidenceId, String>,
    searched: bool,
}

impl NamesDelegate {
    pub fn set_rows(&mut self, rows: Vec<FileRow>, disks: HashMap<EvidenceId, String>) {
        self.rows = rows;
        self.disks = disks;
        self.searched = true;
    }

    fn modified(r: &FileRow) -> String {
        r.modified.and_then(Timestamp::from_unix_secs).map(|t| t.to_string()).unwrap_or_default()
    }
}

impl TableDelegate for NamesDelegate {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.rows.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = COLUMNS[col_ix];
        let col = Column::new(name, name).width(px(width));
        if col_ix == 3 { col.text_right() } else { col }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_header(COLUMNS[col_ix].0.into(), col_ix == 3)
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let text = if self.searched { "No file has a matching name. Names come from indexed disks." } else { "Type part of a name, or a pattern like *.dat." };
        table_empty(text.into())
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(r) = self.rows.get(row_ix) else { return gpui::Empty.into_any_element() };
        let plain = |s: String, color| div().w_full().text_size(t.size_body).text_color(color).truncate().child(s);
        match col_ix {
            0 => h_flex().children(state_badge(&r.state)).into_any_element(),
            1 => plain(r.name.clone(), t.text).into_any_element(),
            2 => mono().w_full().text_size(t.size_body).text_color(t.text_secondary).truncate().child(r.path.clone()).into_any_element(),
            3 => plain(if r.is_dir { String::new() } else { format::bytes(r.size) }, t.text).text_right().into_any_element(),
            4 => mono().text_size(t.size_body).text_color(t.text_secondary).child(Self::modified(r)).into_any_element(),
            _ => plain(self.disks.get(&r.evidence).cloned().unwrap_or_default(), t.text_secondary).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        let Some(r) = self.rows.get(row_ix) else { return String::new() };
        match col_ix {
            0 => r.state.clone(),
            1 => r.name.clone(),
            2 => r.path.clone(),
            3 => r.size.to_string(),
            4 => Self::modified(r),
            _ => String::new(),
        }
    }
}
