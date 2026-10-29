//! The file list: one row per entry of the current folder (or subtree, when filtered),
//! built on demand from the listing, with a tick column for recovery.

use crate::format;
use crate::theme::tokens;
use crate::views::search::state_badge;
use crate::widgets::{Badge, Check, mono, table_empty, table_header};
use gpui::{App, Context, IntoElement, ParentElement, SharedString, Styled, Window, div, px};
use gpui_component::h_flex;
use gpui_component::table::{Column, ColumnSort, TableDelegate, TableState};
use std::collections::BTreeSet;
use strata_workbench::{FileEntryState, FileListing, FileView, Timestamp};

const COLUMNS: [(&str, f32); 8] = [
    ("", 36.),
    ("Name", 280.),
    ("Size", 90.),
    ("Type", 140.),
    ("Created", 172.),
    ("Modified", 172.),
    ("Accessed", 172.),
    ("Path", 380.),
];
const SIZE: usize = 2;

pub fn state_word(state: FileEntryState) -> &'static str {
    match state {
        FileEntryState::Allocated => "Allocated",
        FileEntryState::Deleted => "Deleted",
        FileEntryState::Orphan => "Orphan",
    }
}

fn time(t: Option<Timestamp>) -> String {
    t.map(|t| t.to_string()).unwrap_or_default()
}

#[derive(Default)]
pub struct FilesDelegate {
    listing: Option<FileListing>,
    /// Entry indexes ticked for recovery.
    checked: BTreeSet<usize>,
    empty: &'static str,
}

impl FilesDelegate {
    pub fn set_listing(&mut self, listing: Option<FileListing>, empty: &'static str) {
        self.listing = listing;
        self.checked.clear();
        self.empty = empty;
    }

    pub fn len(&self) -> usize {
        self.listing.as_ref().map_or(0, FileListing::len)
    }

    pub fn row(&self, ix: usize) -> Option<FileView> {
        self.listing.as_ref()?.row(ix)
    }

    pub fn checked(&self) -> Vec<usize> {
        self.checked.iter().copied().collect()
    }

    pub fn check_all(&mut self, on: bool) {
        self.checked.clear();
        if on {
            let all: Vec<usize> = (0..self.len()).filter_map(|i| self.row(i)).map(|r| r.index).collect();
            self.checked.extend(all);
        }
    }

    fn toggle(&mut self, index: usize) {
        if !self.checked.remove(&index) {
            self.checked.insert(index);
        }
    }
}

impl TableDelegate for FilesDelegate {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (name, width) = COLUMNS[col_ix];
        let col = Column::new(SharedString::from(format!("c{col_ix}")), name).width(px(width));
        match col_ix {
            0 => col,
            SIZE => col.sortable().text_right(),
            _ => col.sortable(),
        }
    }

    fn render_th(&mut self, col_ix: usize, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_header(COLUMNS[col_ix].0.into(), col_ix == SIZE)
    }

    fn render_empty(&mut self, _: &mut Window, _: &mut Context<TableState<Self>>) -> impl IntoElement {
        table_empty(self.empty.into())
    }

    fn perform_sort(&mut self, col_ix: usize, sort: ColumnSort, _: &mut Window, _: &mut Context<TableState<Self>>) {
        let Some(listing) = self.listing.as_mut() else { return };
        let desc = sort == ColumnSort::Descending;
        let ts = |t: Option<Timestamp>| t.map_or(i64::MIN, |t| t.unix_secs());
        match col_ix {
            SIZE => listing.sort_by_key(desc, |e| e.size),
            4 => listing.sort_by_key(desc, |e| ts(e.times.created)),
            5 => listing.sort_by_key(desc, |e| ts(e.times.modified)),
            6 => listing.sort_by_key(desc, |e| ts(e.times.accessed)),
            7 => listing.sort_by_key(desc, |e| e.path.to_lowercase()),
            _ => listing.sort_by_key(desc, |e| (!e.is_dir, e.name.to_lowercase())),
        }
    }

    fn render_td(&mut self, row_ix: usize, col_ix: usize, _: &mut Window, cx: &mut Context<TableState<Self>>) -> impl IntoElement {
        let t = tokens();
        let Some(r) = self.row(row_ix) else { return gpui::Empty.into_any_element() };
        let plain = |s: String, color| div().w_full().text_size(t.size_body).text_color(color).truncate().child(s);
        match col_ix {
            0 => {
                let index = r.index;
                let on = self.checked.contains(&index);
                Check::new(SharedString::from(format!("pick-{index}")), "", on, cx.listener(move |table, _, _, cx| {
                    table.delegate_mut().toggle(index);
                    cx.notify();
                }))
                .into_any_element()
            }
            1 => h_flex()
                .gap_2()
                .min_w_0()
                .children(state_badge(state_word(r.state)))
                .child(div().min_w_0().text_size(t.size_body).text_color(if r.is_dir { t.emphasis } else { t.text }).truncate().child(r.name.clone()))
                .children(r.extension_mismatch.then(|| Badge::outline("renamed")))
                .into_any_element(),
            SIZE => plain(if r.is_dir { String::new() } else { format::bytes(r.size) }, t.text).text_right().into_any_element(),
            3 => plain(if r.is_dir { "folder".into() } else { r.detected_type.clone().unwrap_or_default() }, t.text_secondary).into_any_element(),
            4 => mono().text_size(t.size_body).text_color(t.text_secondary).child(time(r.created)).into_any_element(),
            5 => mono().text_size(t.size_body).text_color(t.text_secondary).child(time(r.modified)).into_any_element(),
            6 => mono().text_size(t.size_body).text_color(t.text_secondary).child(time(r.accessed)).into_any_element(),
            _ => mono().w_full().text_size(t.size_body).text_color(t.text_secondary).truncate().child(r.path.clone()).into_any_element(),
        }
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        let Some(r) = self.row(row_ix) else { return String::new() };
        match col_ix {
            1 => r.name,
            SIZE => r.size.to_string(),
            3 => r.detected_type.unwrap_or_default(),
            4 => time(r.created),
            5 => time(r.modified),
            6 => time(r.accessed),
            7 => r.path,
            _ => String::new(),
        }
    }
}
