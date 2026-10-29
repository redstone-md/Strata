//! Search: find text, bytes or a pattern anywhere on the disks (deleted data, free space and
//! deleted partitions included), or find files by name. Matches list with their location and
//! the bytes around them; a match opens 4 KiB either side as hex or text.

mod detail;
mod form;
mod names;
mod results;

pub use names::state_badge;

use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{HexView, flat_table};
use detail::{AROUND, MatchDetail};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    UniformListScrollHandle, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use names::NamesDelegate;
use results::ResultsDelegate;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_workbench::{Encoding, EvidenceId, SearchResultRow};

/// Spacing of result reloads while a search is running.
const LIVE_RELOAD: Duration = Duration::from_secs(1);
/// File-name matches listed at most.
const NAME_LIMIT: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Text,
    Hex,
    Regex,
    Names,
}

impl Mode {
    const ALL: [Mode; 4] = [Mode::Text, Mode::Hex, Mode::Regex, Mode::Names];

    fn label(self) -> &'static str {
        match self {
            Mode::Text => "Text",
            Mode::Hex => "Hex",
            Mode::Regex => "Regex",
            Mode::Names => "File names",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Disk,
    Free,
    Deleted,
    Volume(u32),
}

pub struct SearchView {
    session: Entity<Session>,
    input: Entity<InputState>,
    mode: Mode,
    encodings: Vec<Encoding>,
    case_insensitive: bool,
    area: Area,
    /// `None` = every disk.
    disk: Option<EvidenceId>,
    search: Option<i64>,
    status: Option<SharedString>,
    results: Entity<TableState<ResultsDelegate>>,
    names: Entity<TableState<NamesDelegate>>,
    selected: Option<(SearchResultRow, Arc<Vec<u8>>, u64)>,
    detail_mode: crate::widgets::HexMode,
    scroll: UniformListScrollHandle,
    generation: u64,
    last_load: Instant,
    _subscriptions: Vec<Subscription>,
}

impl SearchView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let wb = session.read(cx).workbench().clone();
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Text, hex bytes, a pattern or a file name"));
        let results = cx.new(|cx| TableState::new(ResultsDelegate::new(wb), window, cx).col_movable(false).sortable(false));
        let names = cx.new(|cx| TableState::new(NamesDelegate::default(), window, cx).col_movable(false).sortable(false));
        let subscriptions = vec![
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
            cx.subscribe_in(&input, window, |this, _, event: &InputEvent, _, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.run(cx);
                }
            }),
            cx.subscribe_in(&results, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event {
                    let row = table.read(cx).delegate().row(*ix).cloned();
                    this.select(row, cx);
                }
            }),
        ];
        let generation = session.read(cx).generation();
        Self {
            session,
            input,
            mode: Mode::Text,
            encodings: vec![Encoding::Utf8, Encoding::Utf16Le, Encoding::Cp1251],
            case_insensitive: true,
            area: Area::Disk,
            disk: None,
            search: None,
            status: None,
            results,
            names,
            selected: None,
            detail_mode: crate::widgets::HexMode::Hex,
            scroll: UniformListScrollHandle::new(),
            generation,
            last_load: Instant::now(),
            _subscriptions: subscriptions,
        }
    }

    /// Put `text` in the field as a text search (from the command bar), ready to run.
    pub fn prefill(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.input.update(cx, |i, cx| i.set_value(text.to_string(), window, cx));
        if self.mode == Mode::Hex {
            self.mode = Mode::Text;
        }
        self.status = None;
        cx.notify();
    }

    fn query_text(&self, cx: &Context<Self>) -> String {
        self.input.read(cx).value().to_string()
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        if session.generation() != self.generation {
            self.generation = session.generation();
            let wb = session.workbench().clone();
            self.search = None;
            self.selected = None;
            self.status = None;
            self.results.update(cx, |t, _| t.delegate_mut().set_workbench(wb));
        } else if self.search.is_some() && (self.last_load.elapsed() >= LIVE_RELOAD || session.snapshot().active_jobs().next().is_none()) {
            self.reload_results(cx);
        }
        cx.notify();
    }

    fn reload_results(&mut self, cx: &mut Context<Self>) {
        self.last_load = Instant::now();
        let wb = self.session.read(cx).workbench().clone();
        if let Some(record) = self.search.and_then(|s| wb.search_record(s).ok().flatten()) {
            self.status = Some(form::status_line(&record).into());
        }
        self.results.update(cx, |t, cx| {
            t.delegate_mut().reload();
            t.refresh(cx);
            cx.notify();
        });
    }

    fn select(&mut self, row: Option<SearchResultRow>, cx: &mut Context<Self>) {
        self.selected = row.map(|r| {
            // Rows start on 16-byte boundaries, like any hex editor.
            let base = r.offset.saturating_sub(AROUND) & !15;
            let len = (r.offset - base) as usize + r.len as usize + AROUND as usize;
            let bytes = self.session.read(cx).workbench().read_disk(r.evidence, base, len).unwrap_or_default();
            if let crate::widgets::HexMode::Text(_) = self.detail_mode {
                self.detail_mode = MatchDetail::text_mode(&r);
            }
            HexView::reveal(&self.scroll, (r.offset - base) as usize, self.detail_mode);
            (r, Arc::new(bytes), base)
        });
        cx.notify();
    }

    fn disk_label(&self, id: EvidenceId, cx: &Context<Self>) -> String {
        self.session.read(cx).snapshot().disk_label(id)
    }
}

impl Render for SearchView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let table = if self.mode == Mode::Names { flat_table(&self.names).into_any_element() } else { flat_table(&self.results).into_any_element() };
        let detail = self.selected.clone().filter(|_| self.mode != Mode::Names).map(|(row, bytes, base)| {
            let this = cx.entity().downgrade();
            let close = std::rc::Rc::new(move |_: &gpui::ClickEvent, _: &mut Window, cx: &mut gpui::App| {
                let _ = this.update(cx, |v, cx| {
                    v.selected = None;
                    cx.notify();
                });
            });
            let this = cx.entity().downgrade();
            let on_mode = std::rc::Rc::new(move |mode, _: &mut Window, cx: &mut gpui::App| {
                let _ = this.update(cx, |v, cx| {
                    v.detail_mode = mode;
                    if let Some((r, _, base)) = &v.selected {
                        HexView::reveal(&v.scroll, (r.offset - base) as usize, mode);
                    }
                    cx.notify();
                });
            });
            let disk = self.disk_label(row.evidence, cx);
            MatchDetail { row, disk, bytes, base, mode: self.detail_mode, scroll: self.scroll.clone(), on_close: close, on_mode }
        });
        h_flex()
            .size_full()
            .items_start()
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .gap(px(14.))
                    .pr(t.gutter)
                    .child(self.form(window, cx))
                    .child(div().flex_1().min_h_0().size_full().child(table)),
            )
            .when_some(detail, |el, d| el.child(d))
    }
}
