//! Geometry and fill of the sector-map grid: pure functions, no GPUI state.

use crate::theme::{grey, tokens};
use gpui::{Bounds, Hsla, Pixels, Point, Size, point, px, size};
use strata_workbench::{BlockClass, SectorCell};

const CELL: f32 = 8.;
const GAP: f32 = 1.;
const PITCH: f32 = CELL + GAP;
/// Columns used before the first paint tells us the real width.
const FALLBACK_COLUMNS: usize = 96;

/// A row-major grid of square cells laid out in a given width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grid {
    pub columns: usize,
    pub rows: usize,
}

impl Grid {
    /// As many columns as fit in `width` (fallback before layout).
    pub fn fit(width: f32, rows: usize) -> Self {
        let columns = if width <= 0.0 { FALLBACK_COLUMNS } else { ((width + GAP) / PITCH).floor().max(1.0) as usize };
        Self { columns, rows: rows.max(1) }
    }

    pub fn cells(self) -> usize {
        self.columns * self.rows
    }

    pub fn height(self) -> Pixels {
        px(self.rows as f32 * PITCH - GAP)
    }

    pub fn cell_bounds(self, origin: Point<Pixels>, index: usize) -> Bounds<Pixels> {
        let (col, row) = ((index % self.columns) as f32, (index / self.columns) as f32);
        Bounds::new(point(origin.x + px(col * PITCH), origin.y + px(row * PITCH)), size(px(CELL), px(CELL)))
    }

    /// The gap just left of a cell, used to mark a volume boundary.
    pub fn boundary_bounds(self, origin: Point<Pixels>, index: usize) -> Bounds<Pixels> {
        let cell = self.cell_bounds(origin, index);
        Bounds::new(point(cell.origin.x - px(GAP), cell.origin.y - px(GAP)), Size { width: px(GAP), height: px(CELL + 2. * GAP) })
    }

    /// Cell under a point relative to the grid's origin.
    pub fn index_at(self, x: f32, y: f32) -> Option<usize> {
        if x < 0.0 || y < 0.0 {
            return None;
        }
        let (col, row) = ((x / PITCH) as usize, (y / PITCH) as usize);
        (col < self.columns && row < self.rows).then_some(row * self.columns + col)
    }
}

/// How one cell is drawn.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CellLook {
    Fill(Hsla),
    /// Unreadable: dark fill with a light outline.
    Damaged,
}

/// Lightness of scanned cells by dominant content (from the disk index), all between the
/// plain scanned tone and the findings range: empty is dim, text is brightest.
pub fn content_tone(class: BlockClass) -> f32 {
    match class {
        BlockClass::Zero | BlockClass::Fill => 0.24,
        BlockClass::Random => 0.42,
        BlockClass::Text => 0.50,
        _ => tokens().cell_scanned.l,
    }
}

/// Findings dominate (brightness up to white on a log scale), then damage, then coverage
/// (toned by content when the disk index knows it).
pub fn look(cell: &SectorCell, max_findings: u32) -> CellLook {
    let t = tokens();
    if cell.findings > 0 {
        let scale = (1.0 + cell.findings as f32).ln() / (1.0 + max_findings.max(1) as f32).ln();
        return CellLook::Fill(grey(0.62 + 0.38 * scale));
    }
    if cell.damaged > 0.0 || cell.content == Some(BlockClass::Unreadable) {
        return CellLook::Damaged;
    }
    let s = cell.scanned.clamp(0.0, 1.0);
    let lerp = |a: f32, b: f32| a + (b - a) * s;
    let done = cell.content.map_or(t.cell_scanned.l, content_tone);
    CellLook::Fill(Hsla { h: 0., s: 0., l: lerp(t.cell_unscanned.l, done), a: 1. })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(scanned: f32, damaged: f32, findings: u32) -> SectorCell {
        SectorCell { scanned, damaged, findings, volume: None, content: None }
    }

    #[test]
    fn fits_columns_and_hit_tests() {
        let g = Grid::fit(9.0 * 10.0 - 1.0, 4);
        assert_eq!(g.columns, 10);
        assert_eq!(g.cells(), 40);
        assert_eq!(g.index_at(0.0, 0.0), Some(0));
        assert_eq!(g.index_at(9.5, 9.5), Some(11));
        assert_eq!(g.index_at(95.0, 0.0), None);
        assert_eq!(Grid::fit(0.0, 2).columns, FALLBACK_COLUMNS);
    }

    #[test]
    fn findings_outrank_damage_and_get_brighter() {
        assert!(matches!(look(&cell(1.0, 0.5, 0), 10), CellLook::Damaged));
        let (CellLook::Fill(one), CellLook::Fill(many)) = (look(&cell(1.0, 0.5, 1), 10), look(&cell(1.0, 0.0, 10), 10)) else {
            panic!("findings are filled");
        };
        assert!(many.l > one.l && (many.l - 1.0).abs() < 1e-3);
        let (CellLook::Fill(empty), CellLook::Fill(done)) = (look(&cell(0.0, 0.0, 0), 0), look(&cell(1.0, 0.0, 0), 0)) else {
            panic!("plain cells are filled");
        };
        assert!(done.l > empty.l);
    }

    #[test]
    fn content_tones_stay_below_findings() {
        let toned = |class| {
            let CellLook::Fill(c) = look(&SectorCell { content: Some(class), ..cell(1.0, 0.0, 0) }, 0) else { panic!("filled") };
            c.l
        };
        assert!(toned(BlockClass::Zero) < toned(BlockClass::Binary));
        assert!(toned(BlockClass::Binary) < toned(BlockClass::Random) && toned(BlockClass::Random) < toned(BlockClass::Text));
        assert!(toned(BlockClass::Text) < 0.62);
        assert!(matches!(look(&SectorCell { content: Some(BlockClass::Unreadable), ..cell(1.0, 0.0, 0) }, 0), CellLook::Damaged));
    }
}
