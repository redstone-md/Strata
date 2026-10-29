//! One disk drawn as a grid of cells: coverage, unreadable areas, finding density and volume
//! boundaries. Hovering a cell shows its byte range and state in the line under the grid.

use super::grid::{CellLook, Grid, look};
use crate::format;
use crate::theme::tokens;
use crate::widgets::{loading_edge, mono, quiet};
use gpui::{
    AnyElement, BorderStyle, Context, DispatchPhase, IntoElement, MouseMoveEvent, ParentElement, Render, Styled,
    Window, canvas, div, fill, px, quad,
};
use gpui_component::{h_flex, v_flex};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_workbench::{EvidenceId, SectorCell, SectorMap, Workbench};

/// Minimum spacing between automatic refetches while a job is running.
const STALE: Duration = Duration::from_secs(2);

/// One volume as named under the map.
#[derive(Clone, PartialEq)]
pub struct VolumeLabel {
    pub index: u32,
    pub name: String,
    pub size: String,
}

pub struct SectorMapView {
    workbench: Arc<Workbench>,
    evidence: EvidenceId,
    rows: usize,
    map: Option<Rc<SectorMap>>,
    error: Option<String>,
    fetched: Instant,
    /// A refetch is due; the current map stays on screen until the new one lands.
    stale: bool,
    /// A fetch runs on a background thread.
    loading: bool,
    volumes: Vec<VolumeLabel>,
    /// Live scan coverage 0..=1; the stored map lags behind a running scan.
    coverage: f32,
    /// Width of the last paint; the next render fits its columns to it.
    width: Rc<Cell<f32>>,
    hovered: Rc<Cell<Option<usize>>>,
}

impl SectorMapView {
    pub fn new(workbench: Arc<Workbench>, evidence: EvidenceId, rows: usize) -> Self {
        Self {
            workbench,
            evidence,
            rows,
            map: None,
            error: None,
            fetched: Instant::now(),
            stale: false,
            loading: false,
            volumes: Vec::new(),
            coverage: 0.0,
            width: Rc::new(Cell::new(0.0)),
            hovered: Rc::new(Cell::new(None)),
        }
    }

    pub fn set_volumes(&mut self, volumes: Vec<VolumeLabel>) {
        self.volumes = volumes;
    }

    pub fn set_coverage(&mut self, coverage: f32) {
        self.coverage = coverage.clamp(0.0, 1.0);
    }

    /// Refetch now (`force`) or when the cached map is older than [`STALE`].
    pub fn refresh(&mut self, force: bool, cx: &mut Context<Self>) {
        if force || self.fetched.elapsed() >= STALE {
            self.stale = true;
            cx.notify();
        }
    }

    /// Fetch the map for `grid` on a background thread when it is missing, the wrong size or
    /// stale. On a large case the density query takes seconds; it must not stall a frame.
    fn ensure(&mut self, grid: Grid, cx: &mut Context<Self>) {
        let fits = self.map.as_ref().is_some_and(|m| m.cells.len() == grid.cells());
        if self.loading || (fits && !self.stale) {
            return;
        }
        self.loading = true;
        self.stale = false;
        self.fetched = Instant::now();
        let (wb, evidence, cells) = (self.workbench.clone(), self.evidence, grid.cells());
        cx.spawn(async move |this, cx| {
            let map = cx.background_executor().spawn(async move { wb.sector_map(evidence, cells) }).await;
            let _ = this.update(cx, |v, cx| {
                v.loading = false;
                v.fetched = Instant::now();
                match map {
                    Ok(map) => {
                        v.map = Some(Rc::new(map));
                        v.error = None;
                    }
                    Err(e) => v.error = Some(format!("Cannot draw the sector map: {e}")),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn grid_canvas(&self, map: Rc<SectorMap>, grid: Grid) -> impl IntoElement {
        let width = self.width.clone();
        let hovered = self.hovered.clone();
        let covered = (self.coverage as f64 * map.disk_len as f64) as u64;
        canvas(
            |_, _, _| (),
            move |bounds, (), window, _| {
                let t = tokens();
                if (bounds.size.width.as_f32() - width.get()).abs() >= 1.0 {
                    width.set(bounds.size.width.as_f32());
                    window.refresh();
                }
                let max = map.cells.iter().map(|c| c.findings).max().unwrap_or(0);
                let origin = bounds.origin;
                for (i, cell) in map.cells.iter().enumerate().take(grid.cells()) {
                    let b = grid.cell_bounds(origin, i);
                    let live = covered.saturating_sub(i as u64 * map.cell_len) as f32 / map.cell_len.max(1) as f32;
                    let cell = SectorCell { scanned: cell.scanned.max(live.min(1.0)), ..*cell };
                    match look(&cell, max) {
                        CellLook::Fill(color) => window.paint_quad(fill(b, color)),
                        CellLook::Damaged => {
                            window.paint_quad(quad(b, px(0.), t.cell_damaged, px(1.), t.text_secondary, BorderStyle::Solid))
                        }
                    }
                    if i > 0 && i % grid.columns != 0 && map.cells[i - 1].volume != cell.volume {
                        window.paint_quad(fill(grid.boundary_bounds(origin, i), t.emphasis));
                    }
                }
                if let Some(i) = hovered.get().filter(|i| *i < map.cells.len()) {
                    let b = grid.cell_bounds(origin, i).dilate(px(1.));
                    window.paint_quad(quad(b, px(0.), gpui::transparent_black(), px(1.), t.emphasis, BorderStyle::Solid));
                }
                let hovered = hovered.clone();
                window.on_mouse_event(move |e: &MouseMoveEvent, phase, window, _| {
                    if phase != DispatchPhase::Bubble {
                        return;
                    }
                    let rel = e.position - bounds.origin;
                    let hit = bounds.contains(&e.position).then(|| grid.index_at(rel.x.as_f32(), rel.y.as_f32())).flatten();
                    if hovered.get() != hit {
                        hovered.set(hit);
                        window.refresh();
                    }
                });
            },
        )
        .w_full()
        .h(grid.height())
    }

    /// The line under the grid: the hovered cell, or the volumes when nothing is hovered.
    fn status_line(&self, map: &SectorMap) -> AnyElement {
        let t = tokens();
        let line = h_flex().h(px(18.)).gap(px(20.)).text_size(t.size_small).text_color(t.text_secondary);
        if let Some(i) = self.hovered.get().filter(|i| *i < map.cells.len()) {
            let cell = map.cells[i];
            let start = i as u64 * map.cell_len;
            let end = (start + map.cell_len).min(map.disk_len);
            let findings = match cell.findings {
                0 => "no findings".to_string(),
                1 => "1 finding".to_string(),
                n => format!("{n} findings"),
            };
            return line
                .child(mono().text_color(t.text).child(format!("{}–{}", format::hex_offset(start), format::hex_offset(end))))
                .child(format!("{} scanned", format::percent(cell.scanned)))
                .child(div().text_color(if cell.findings > 0 { t.emphasis } else { t.text_secondary }).child(findings))
                .children((cell.damaged > 0.0).then(|| format!("{} unreadable", format::percent(cell.damaged))))
                .children(cell.volume.map(|v| format!("volume {v}")))
                .into_any_element();
        }
        if self.volumes.is_empty() {
            return line.child("No partitions or filesystems recognised").into_any_element();
        }
        line.children(self.volumes.iter().map(|v| {
            h_flex()
                .gap(px(6.))
                .child(format!("{}", v.index))
                .child(div().text_color(t.text).child(v.name.clone()))
                .child(v.size.clone())
        }))
        .into_any_element()
    }
}

impl Render for SectorMapView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let grid = Grid::fit(self.width.get(), self.rows);
        self.ensure(grid, cx);
        // A map fetched for another width is not drawn; the refit one follows.
        let map = self.map.as_ref().filter(|m| m.cells.len() == grid.cells());
        let body = match (map, &self.error) {
            (_, Some(e)) => quiet().child(e.clone()).into_any_element(),
            (Some(map), None) => v_flex()
                .gap(px(8.))
                .child(self.grid_canvas(map.clone(), grid))
                .child(self.status_line(map))
                .into_any_element(),
            (None, None) => div().h(grid.height()).relative().child(loading_edge(("map-loading", self.evidence.get() as usize))).into_any_element(),
        };
        div().w_full().min_w_0().child(body)
    }
}
