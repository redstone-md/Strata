//! Sector maps of every disk in the case, shared by the Overview and Disks screens (only one
//! of them is on screen at a time, so each disk keeps one map view and one fetch).

mod grid;
mod view;

pub use view::SectorMapView;

use crate::format;
use crate::session::{DiskSummary, Session};
use gpui::{AppContext as _, Context, Entity, Subscription};
use std::collections::HashMap;
use strata_workbench::EvidenceId;
use view::VolumeLabel;

/// Grid rows per disk; columns follow the available width.
const ROWS: usize = 12;

pub struct DiskMaps {
    session: Entity<Session>,
    maps: HashMap<EvidenceId, Entity<SectorMapView>>,
    generation: u64,
    was_active: bool,
    _observe: Subscription,
}

impl DiskMaps {
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&session, |this, _, cx| this.sync(cx));
        let generation = session.read(cx).generation();
        let mut this = Self { session, maps: HashMap::new(), generation, was_active: false, _observe: observe };
        this.sync(cx);
        this
    }

    pub fn get(&self, id: EvidenceId) -> Option<Entity<SectorMapView>> {
        self.maps.get(&id).cloned()
    }

    fn volumes(disk: &DiskSummary) -> Vec<VolumeLabel> {
        disk.record
            .volumes
            .iter()
            .map(|v| VolumeLabel {
                index: v.index,
                name: format::volume_name(&format!("{:?}", v.fs), &format!("{:?}", v.origin)),
                size: format::bytes(v.range.len()),
            })
            .collect()
    }

    /// Follow the session: new disks get a map, removed ones lose it, maps refetch while jobs
    /// run (throttled) and once more when the last job ends.
    fn sync(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let workbench = session.workbench().clone();
        let snapshot = session.snapshot().clone();
        let active = snapshot.active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            self.maps.clear();
        }
        let finished = self.was_active && !active;
        self.was_active = active;
        self.maps.retain(|id, _| snapshot.disks.iter().any(|d| d.id() == *id));
        for disk in &snapshot.disks {
            let volumes = Self::volumes(disk);
            match self.maps.get(&disk.id()) {
                Some(map) => map.update(cx, |m, cx| {
                    m.set_volumes(volumes);
                    m.set_coverage(disk.scanned);
                    if active || finished {
                        m.refresh(finished, cx);
                    }
                }),
                None => {
                    let (wb, id) = (workbench.clone(), disk.id());
                    let map = cx.new(|_| {
                        let mut m = SectorMapView::new(wb, id, ROWS);
                        m.set_volumes(volumes);
                        m.set_coverage(disk.scanned);
                        m
                    });
                    self.maps.insert(id, map);
                }
            }
        }
        cx.notify();
    }
}

/// Key to the cell fills, shown once beside the maps.
pub fn legend() -> impl gpui::IntoElement {
    use crate::theme::{grey, tokens};
    use gpui::{ParentElement as _, Styled as _, div, px};
    let t = tokens();
    let swatch = |fill: gpui::Hsla, outline: bool| {
        let s = div().size(px(8.)).bg(fill);
        if outline { s.border_1().border_color(t.text_secondary) } else { s }
    };
    let item = |s: gpui::Div, label: &'static str| {
        gpui_component::h_flex().gap(px(6.)).child(s).child(label)
    };
    gpui_component::h_flex()
        .gap(px(16.))
        .text_size(t.size_small)
        .text_color(t.text_secondary)
        .child(item(swatch(t.cell_unscanned, false), "Not scanned"))
        .child(item(swatch(t.cell_scanned, false), "Scanned"))
        .child(item(swatch(t.cell_damaged, true), "Unreadable"))
        .child(item(swatch(grey(1.0), false), "Findings"))
}
