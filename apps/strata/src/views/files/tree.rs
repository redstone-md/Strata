//! Left pane of Files: disks, their volumes and folders, loaded one level at a time as the
//! user opens them.

use crate::session::DiskSummary;
use crate::theme::tokens;
use crate::widgets::Badge;
use gpui::{
    App, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _, Styled,
    Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{Icon, IconName, h_flex, v_flex};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use strata_workbench::{DirNode, EvidenceId, FileEntryState, VolumeOrigin, Workbench};

const INDENT: f32 = 14.;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Disk(EvidenceId),
    Volume(EvidenceId, u32),
    Dir(EvidenceId, u32, usize),
}

impl NodeKey {
    /// `(disk, volume, folder)` a node lists, `None` for disk nodes.
    pub fn place(self) -> Option<(EvidenceId, u32, Option<usize>)> {
        match self {
            Self::Disk(_) => None,
            Self::Volume(e, v) => Some((e, v, None)),
            Self::Dir(e, v, d) => Some((e, v, Some(d))),
        }
    }
}

#[derive(Clone)]
pub struct TreeRow {
    pub key: NodeKey,
    pub depth: usize,
    pub label: String,
    pub expandable: bool,
    pub open: bool,
    pub quiet: bool,
    pub badge: Option<&'static str>,
}

#[derive(Default)]
pub struct FolderTree {
    open: HashSet<NodeKey>,
    children: HashMap<NodeKey, Vec<DirNode>>,
}

impl FolderTree {
    pub fn clear(&mut self) {
        self.open.clear();
        self.children.clear();
    }

    /// Forget loaded folders (volumes changed); keep what is open.
    pub fn forget_children(&mut self) {
        self.children.clear();
    }

    pub fn toggle(&mut self, key: NodeKey) {
        if !self.open.remove(&key) {
            self.open.insert(key);
        }
    }

    pub fn open(&mut self, key: NodeKey) {
        self.open.insert(key);
    }

    fn subdirs(&mut self, wb: &Workbench, key: NodeKey) -> Vec<DirNode> {
        let Some((e, v, d)) = key.place() else { return Vec::new() };
        self.children.entry(key).or_insert_with(|| wb.subdirs(e, v, d).unwrap_or_default()).clone()
    }

    fn folders(&mut self, wb: &Workbench, e: EvidenceId, v: u32, key: NodeKey, depth: usize, out: &mut Vec<TreeRow>) {
        for d in self.subdirs(wb, key) {
            let child = NodeKey::Dir(e, v, d.index);
            let open = self.open.contains(&child);
            let deleted = d.state == FileEntryState::Deleted;
            let quiet = d.state != FileEntryState::Allocated;
            out.push(TreeRow { key: child, depth, label: d.name.clone(), expandable: d.has_subdirs, open, quiet, badge: deleted.then_some("deleted") });
            if open {
                self.folders(wb, e, v, child, depth + 1, out);
            }
        }
    }

    /// Visible rows: every disk, the volumes of open disks, the folders of open nodes.
    pub fn rows(&mut self, disks: &[DiskSummary], wb: &Workbench) -> Vec<TreeRow> {
        let mut out = Vec::new();
        for disk in disks {
            let key = NodeKey::Disk(disk.id());
            let open = self.open.contains(&key);
            out.push(TreeRow { key, depth: 0, label: disk.record.info.label.clone(), expandable: !disk.record.volumes.is_empty(), open, quiet: false, badge: None });
            if !open {
                continue;
            }
            for v in &disk.record.volumes {
                let key = NodeKey::Volume(disk.id(), v.index);
                let open = self.open.contains(&key);
                let recovered = v.origin == VolumeOrigin::Recovered;
                let label = format!("V{} {}", v.index, v.fs.name());
                out.push(TreeRow { key, depth: 1, label, expandable: true, open, quiet: false, badge: recovered.then_some("deleted partition") });
                if open {
                    self.folders(wb, disk.id(), v.index, key, 2, &mut out);
                }
            }
        }
        out
    }
}

type SelectHandler = Rc<dyn Fn(NodeKey, &mut Window, &mut App)>;

/// The rendered pane.
#[derive(IntoElement)]
pub struct TreePane {
    rows: Vec<TreeRow>,
    selected: Option<NodeKey>,
    on_select: SelectHandler,
}

impl TreePane {
    pub fn new(rows: Vec<TreeRow>, selected: Option<NodeKey>, on_select: impl Fn(NodeKey, &mut Window, &mut App) + 'static) -> Self {
        Self { rows, selected, on_select: Rc::new(on_select) }
    }
}

impl RenderOnce for TreePane {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let rows = self.rows.into_iter().enumerate().map(|(i, r)| {
            let active = self.selected == Some(r.key);
            let handler = self.on_select.clone();
            let key = r.key;
            let color = if active { t.emphasis } else if r.quiet { t.text_secondary } else { t.text };
            h_flex()
                .id(SharedString::from(format!("tree-{i}")))
                .h(px(26.))
                .pl(px(8. + INDENT * r.depth as f32))
                .pr(px(8.))
                .gap(px(6.))
                .min_w_0()
                .cursor_pointer()
                .rounded(t.radius)
                .text_size(t.size_body)
                .text_color(color)
                .when(active, |el| el.bg(t.selection))
                .when(!active, |el| el.hover(|s| s.bg(t.hover)))
                .child(div().w(px(12.)).flex_shrink_0().when(r.expandable, |el| {
                    el.child(Icon::new(if r.open { IconName::ChevronDown } else { IconName::ChevronRight }).size(px(12.)).text_color(t.text_secondary))
                }))
                .child(div().min_w_0().truncate().child(r.label))
                .children(r.badge.map(Badge::outline))
                .on_click(move |_, w, cx| handler(key, w, cx))
        });
        v_flex().py(px(4.)).children(rows)
    }
}
