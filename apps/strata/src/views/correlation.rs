//! Correlation: where several disks share findings or complement each other's files.

use crate::categories;
use crate::format;
use crate::session::{Session, Snapshot};
use crate::theme::tokens;
use crate::widgets::{Cell, Section, TextTable, flat_table};
use gpui::{AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window, div, px};
use gpui_component::table::TableState;
use gpui_component::v_flex;

pub struct CorrelationView {
    session: Entity<Session>,
    shared: Entity<TableState<TextTable>>,
    complements: Entity<TableState<TextTable>>,
}

impl CorrelationView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let shared = cx.new(|cx| {
            TableState::new(
                TextTable::new(
                    vec![("Category", 130., Cell::Text), ("Value", 460., Cell::Data), ("Disks", 260., Cell::Text), ("Occurrences", 110., Cell::Number)],
                    "No value was found on more than one disk.",
                ),
                window,
                cx,
            )
        });
        let complements = cx.new(|cx| {
            TableState::new(
                TextTable::new(
                    vec![("Path", 460., Cell::Data), ("Copies per disk", 520., Cell::Text), ("Disks", 80., Cell::Number)],
                    "No file differs between disks.",
                ),
                window,
                cx,
            )
        });
        let mut this = Self { session, shared, complements };
        this.reload(cx);
        this
    }

    /// Re-run both correlation queries (on screen activation; they scan the whole case).
    pub fn reload(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let wb = session.workbench().clone();
        let snapshot = session.snapshot().clone();
        let disks = |ids: &mut dyn Iterator<Item = String>| ids.collect::<Vec<_>>().join(", ");
        let shared_rows = wb
            .shared_findings()
            .unwrap_or_default()
            .into_iter()
            .map(|f| {
                row([
                    categories::label(f.category).to_string(),
                    f.value,
                    disks(&mut f.evidence.iter().map(|e| snapshot.disk_label(*e))),
                    f.occurrences.to_string(),
                ])
            })
            .collect();
        let complement_rows = wb
            .file_complements()
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let copies = Self::copies(&snapshot, &c.copies);
                row([c.path, copies, c.copies.len().to_string()])
            })
            .collect();
        Self::fill(&self.shared, shared_rows, cx);
        Self::fill(&self.complements, complement_rows, cx);
        cx.notify();
    }

    fn copies(snapshot: &Snapshot, copies: &[(strata_workbench::EvidenceId, String, u64)]) -> String {
        copies
            .iter()
            .map(|(e, state, size)| format!("{}: {state} {}", snapshot.disk_label(*e), format::bytes(*size)))
            .collect::<Vec<_>>()
            .join(";  ")
    }

    fn fill(table: &Entity<TableState<TextTable>>, rows: Vec<Vec<SharedString>>, cx: &mut Context<Self>) {
        table.update(cx, |t, cx| {
            t.delegate_mut().set_rows(rows);
            t.refresh(cx);
            cx.notify();
        });
    }

    fn section(title: &'static str, note: String, table: &Entity<TableState<TextTable>>) -> impl IntoElement {
        Section::new(title).note(note).flex_1().min_h_0().child(div().flex_1().min_h_0().size_full().child(flat_table(table)))
    }
}

fn row<const N: usize>(cells: [String; N]) -> Vec<SharedString> {
    cells.into_iter().map(SharedString::from).collect()
}

impl Render for CorrelationView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let shared = self.shared.read(cx).delegate().len() as u64;
        let complements = self.complements.read(cx).delegate().len() as u64;
        v_flex()
            .size_full()
            .pr(t.gutter)
            .gap(px(32.))
            .child(Self::section(
                "Values found on several disks",
                format::count(shared, "value", "values"),
                &self.shared,
            ))
            .child(Self::section(
                "Files that differ between disks",
                format!("{}; one copy may fill another's gaps", format::count(complements, "path", "paths")),
                &self.complements,
            ))
    }
}
