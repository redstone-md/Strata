//! Files: browse every parsed volume (deleted partitions included) as a folder tree and a
//! flat list with deleted and orphaned entries, filter it, preview a file, and recover a
//! selection to a folder.

mod delegate;
mod preview;
mod tree;

use crate::picker::{PickKind, pick_path};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Choice, Field, HexView, TextButton, flat_table, quiet};
use delegate::FilesDelegate;
use gpui::{
    AppContext as _, ClickEvent, Context, Entity, InteractiveElement as _, IntoElement, ParentElement, Render, SharedString,
    StatefulInteractiveElement as _, Styled, Subscription, UniformListScrollHandle, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use preview::{FilePreview, PREVIEW_BYTES};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use strata_workbench::{EvidenceId, FileFilter, FileListQuery, FileView, TypeCategory};
use tree::{FolderTree, NodeKey, TreePane};

const TREE_WIDTH: f32 = 280.;
const FILTERS: [(&str, FileFilter); 9] = [
    ("All", FileFilter::All),
    ("Deleted", FileFilter::Deleted),
    ("Orphaned", FileFilter::Orphan),
    ("Renamed", FileFilter::Renamed),
    ("Documents", FileFilter::Type(TypeCategory::Document)),
    ("Images", FileFilter::Type(TypeCategory::Image)),
    ("Archives", FileFilter::Type(TypeCategory::Archive)),
    ("Wallets", FileFilter::Type(TypeCategory::Wallet)),
    ("Databases", FileFilter::Type(TypeCategory::Database)),
];

pub struct FilesView {
    session: Entity<Session>,
    tree: FolderTree,
    /// The folder listed: `(disk, volume, folder)`; `None` folder = volume root.
    place: Option<(EvidenceId, u32, Option<usize>)>,
    filter: usize,
    name: Entity<InputState>,
    table: Entity<TableState<FilesDelegate>>,
    types: HashMap<EvidenceId, Arc<strata_workbench::FileTypes>>,
    preview: Option<(FileView, Arc<Vec<u8>>)>,
    preview_mode: crate::widgets::HexMode,
    scroll: UniformListScrollHandle,
    message: Option<SharedString>,
    /// Path of the folder on show, for the header.
    place_path: String,
    generation: u64,
    volumes_seen: usize,
    _subscriptions: Vec<Subscription>,
}

impl FilesView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let name = cx.new(|cx| InputState::new(window, cx).placeholder("Filter by name"));
        let table = cx.new(|cx| TableState::new(FilesDelegate::default(), window, cx).col_movable(false));
        let subscriptions = vec![
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
            cx.subscribe_in(&name, window, |this, _, event: &InputEvent, _, cx| {
                if let InputEvent::Change = event {
                    this.reload(cx);
                }
            }),
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| match event {
                TableEvent::SelectRow(ix) => {
                    let row = table.read(cx).delegate().row(*ix);
                    this.show_preview(row, cx);
                }
                TableEvent::DoubleClickedRow(ix) => {
                    if let Some(r) = table.read(cx).delegate().row(*ix).filter(|r| r.is_dir) {
                        this.open_place(NodeKey::Dir(r.evidence, r.volume, r.index), cx);
                    }
                }
                _ => {}
            }),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            tree: FolderTree::default(),
            place: None,
            filter: 0,
            name,
            table,
            types: HashMap::new(),
            preview: None,
            preview_mode: crate::widgets::HexMode::Hex,
            scroll: UniformListScrollHandle::new(),
            message: None,
            place_path: String::new(),
            generation,
            volumes_seen: 0,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    fn volume_count(&self, cx: &Context<Self>) -> usize {
        self.session.read(cx).snapshot().disks.iter().map(|d| d.record.volumes.len()).sum()
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            self.tree.clear();
            self.place = None;
            self.preview = None;
            self.types.clear();
            self.reload(cx);
        } else if !active && self.volume_count(cx) != self.volumes_seen {
            // Volumes appeared (a recovered partition) or the case finished indexing.
            self.tree.forget_children();
            self.types.clear();
            self.reload(cx);
        }
        cx.notify();
    }

    /// Show one volume or folder (from the Disks screen, the tree or a double click).
    pub fn open_place(&mut self, key: NodeKey, cx: &mut Context<Self>) {
        if let NodeKey::Volume(e, _) | NodeKey::Dir(e, _, _) = key {
            self.tree.open(NodeKey::Disk(e));
        }
        if let NodeKey::Dir(e, v, _) = key {
            self.tree.open(NodeKey::Volume(e, v));
        }
        self.tree.open(key);
        self.place = key.place();
        self.place_path = match key {
            NodeKey::Dir(e, v, d) => self.session.read(cx).workbench().entry_path(e, v, d).unwrap_or_default(),
            _ => String::new(),
        };
        self.preview = None;
        self.reload(cx);
    }

    pub fn open_volume(&mut self, evidence: EvidenceId, volume: u32, cx: &mut Context<Self>) {
        self.open_place(NodeKey::Volume(evidence, volume), cx);
    }

    fn pick_node(&mut self, key: NodeKey, cx: &mut Context<Self>) {
        match key {
            NodeKey::Disk(_) => {
                self.tree.toggle(key);
                cx.notify();
            }
            _ if self.place == key.place() => {
                self.tree.toggle(key);
                cx.notify();
            }
            _ => self.open_place(key, cx),
        }
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        self.volumes_seen = self.volume_count(cx);
        let wb = self.session.read(cx).workbench().clone();
        let Some((evidence, volume, dir)) = self.place else {
            let empty = if self.session.read(cx).snapshot().disks.is_empty() { "Add a disk on the Disks screen first." } else { "Pick a volume or folder on the left." };
            self.table.update(cx, |t, cx| {
                t.delegate_mut().set_listing(None, empty);
                t.refresh(cx);
            });
            return cx.notify();
        };
        let types = self.types.entry(evidence).or_insert_with(|| wb.file_types(evidence).unwrap_or_default()).clone();
        let q = FileListQuery {
            evidence,
            volume,
            dir,
            filter: FILTERS.get(self.filter).map_or(FileFilter::All, |f| f.1),
            name: self.name.read(cx).value().to_string(),
        };
        let listing = wb.list_files(&q, types).ok();
        let empty = if listing.is_some() { "Nothing here matches." } else { "This volume's filesystem could not be read." };
        self.table.update(cx, |t, cx| {
            t.delegate_mut().set_listing(listing, empty);
            t.refresh(cx);
        });
        cx.notify();
    }

    fn show_preview(&mut self, row: Option<FileView>, cx: &mut Context<Self>) {
        self.preview = row.filter(|r| !r.is_dir).map(|r| {
            let bytes = self.session.read(cx).workbench().read_file(r.evidence, r.volume, r.index, 0, PREVIEW_BYTES).unwrap_or_default();
            (r, Arc::new(bytes))
        });
        HexView::reveal(&self.scroll, 0, crate::widgets::HexMode::Hex);
        cx.notify();
    }

    /// Ticked entries, else the selected row, else the folder on show.
    fn selection(&self, cx: &Context<Self>) -> (Vec<usize>, String) {
        let d = self.table.read(cx).delegate();
        let checked = d.checked();
        if !checked.is_empty() {
            let n = checked.len();
            return (checked, format!("{n} ticked {}", if n == 1 { "item" } else { "items" }));
        }
        if let Some((f, _)) = &self.preview {
            return (vec![f.index], f.name.clone());
        }
        let all: Vec<usize> = (0..d.len()).filter_map(|i| d.row(i)).map(|r| r.index).collect();
        let n = all.len();
        (all, format!("all {n} listed {}", if n == 1 { "item" } else { "items" }))
    }

    fn recover(&mut self, cx: &mut Context<Self>) {
        let Some((evidence, volume, _)) = self.place else { return };
        let (selection, what) = self.selection(cx);
        if selection.is_empty() {
            self.message = Some("Nothing to recover here.".into());
            return cx.notify();
        }
        let this = cx.entity().downgrade();
        pick_path(PickKind::Folder, cx, move |dest, cx| {
            let _ = this.update(cx, |v, cx| {
                v.session.update(cx, |s, cx| {
                    s.workbench().recover_files(evidence, volume, selection, dest.clone());
                    s.watch_jobs(cx);
                });
                v.message = Some(format!("Recovering {what} to {}. Deleted files whose clusters were reused get a .partial suffix; see recovery-log.csv.", dest.display()).into());
                cx.notify();
            });
        });
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let d = self.table.read(cx).delegate();
        let n = d.len() as u64;
        let ticked = d.checked().len();
        let place = self.place.map(|(e, v, _)| {
            let disk = self.session.read(cx).snapshot().disk_label(e);
            let folder = if self.place_path.is_empty() { String::new() } else { format!(" / {}", self.place_path) };
            format!("{disk} / V{v}{folder}")
        });
        let filters = FILTERS.iter().map(|f| SharedString::from(f.0)).collect();
        let this = cx.entity().downgrade();
        let pick_filter = move |i: usize, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |v, cx| {
                v.filter = i;
                v.reload(cx);
            });
        };
        let tick_label = if ticked > 0 { "Clear ticks" } else { "Tick all" };
        v_flex()
            .gap(px(10.))
            .child(
                h_flex()
                    .h(px(32.))
                    .gap(px(16.))
                    .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Files"))
                    .children(place.map(|p| div().min_w_0().text_size(t.size_body).text_color(t.text).truncate().child(p)))
                    .child(quiet().flex_shrink_0().child(crate::format::count(n, "entry", "entries")))
                    .children((ticked > 0).then(|| quiet().flex_shrink_0().child(format!("{ticked} ticked"))))
                    .child(div().flex_1())
                    .child(div().w(px(240.)).flex_shrink_0().child(Field::new(&self.name))),
            )
            .child(
                h_flex()
                    .gap(px(12.))
                    .child(Choice::new("file-filter", filters, self.filter, pick_filter))
                    .child(div().flex_1())
                    .child(TextButton::new("tick-all", tick_label).on_click(cx.listener(move |this, _, _, cx| {
                        this.table.update(cx, |t, cx| {
                            t.delegate_mut().check_all(ticked == 0);
                            cx.notify();
                        });
                        cx.notify();
                    })))
                    .child(TextButton::new("recover", "Recover to folder…").strong().on_click(cx.listener(|this, _, _, cx| this.recover(cx)))),
            )
            .children(self.message.clone().map(|m| div().text_size(t.size_body).text_color(t.text).child(m)))
    }
}

impl Render for FilesView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let wb = self.session.read(cx).workbench().clone();
        let rows = self.tree.rows(&snapshot.disks, &wb);
        let selected = self.place.map(|(e, v, d)| d.map_or(NodeKey::Volume(e, v), |d| NodeKey::Dir(e, v, d)));
        let this = cx.entity().downgrade();
        let tree = TreePane::new(rows, selected, move |key, _, cx| {
            let _ = this.update(cx, |v, cx| v.pick_node(key, cx));
        });
        let preview = self.preview.clone().map(|(file, bytes)| {
            let this = cx.entity().downgrade();
            let close: Rc<dyn Fn(&ClickEvent, &mut Window, &mut gpui::App)> = Rc::new(move |_, _, cx| {
                let _ = this.update(cx, |v, cx| {
                    v.preview = None;
                    cx.notify();
                });
            });
            let this = cx.entity().downgrade();
            let on_mode: Rc<dyn Fn(crate::widgets::HexMode, &mut Window, &mut gpui::App)> = Rc::new(move |mode, _, cx| {
                let _ = this.update(cx, |v, cx| {
                    v.preview_mode = mode;
                    cx.notify();
                });
            });
            FilePreview { file, bytes, mode: self.preview_mode, scroll: self.scroll.clone(), on_close: close, on_mode }
        });
        h_flex()
            .size_full()
            .items_start()
            .child(
                div()
                    .id("files-tree")
                    .w(px(TREE_WIDTH))
                    .flex_shrink_0()
                    .h_full()
                    .overflow_y_scroll()
                    .pr(px(12.))
                    .border_r_1()
                    .border_color(t.rule)
                    .child(tree),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .gap(px(12.))
                    .pl(px(20.))
                    .pr(t.gutter)
                    .child(self.header(cx))
                    .child(div().flex_1().min_h_0().size_full().child(flat_table(&self.table)))
                    .when_some(preview, |el, p| el.child(p)),
            )
    }
}
