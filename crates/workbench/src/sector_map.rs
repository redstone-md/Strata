//! Disk overview as a grid of cells, like a ddrescue map: what was read, what is unreadable,
//! where findings cluster and where volumes lie.

use serde::Serialize;
use strata_case::Case;
use strata_index::{BlockClass, DiskIndex};
use strata_kernel::{ByteRange, EvidenceId, Result};

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SectorCell {
    /// 0..=1 of the cell already scanned.
    pub scanned: f32,
    /// 0..=1 of the cell unreadable on the medium.
    pub damaged: f32,
    /// Findings (keys, wallets, seeds, addresses, identities) starting in the cell.
    pub findings: u32,
    /// Index of the volume covering the cell's start, if any.
    pub volume: Option<u32>,
    /// Dominant content of the cell from the disk index (`None` without an index).
    pub content: Option<BlockClass>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectorMap {
    pub disk_len: u64,
    pub cell_len: u64,
    pub cells: Vec<SectorCell>,
}

impl SectorMap {
    pub fn build(case: &Case, id: EvidenceId, cells: usize) -> Result<Self> {
        let cells = cells.max(1);
        let source = case.source(id)?;
        let disk_len = source.len().max(1);
        let cell_len = disk_len.div_ceil(cells as u64).max(1);
        let cell = |i: usize| ByteRange::new(i as u64 * cell_len, cell_len.min(disk_len.saturating_sub(i as u64 * cell_len)));
        let scanned_to = case.scan_state(id)?.map_or(0, |(mark, _, done)| if done { disk_len } else { mark });
        let damage = source.damage();
        let volumes = case.record(id)?.volumes;
        let density = case.finding_density(id, cell_len)?;
        let out = (0..cells)
            .map(|i| {
                let r = cell(i);
                let len = r.len().max(1) as f32;
                SectorCell {
                    scanned: r.covered_by(&[ByteRange::from_bounds(0, scanned_to)]) as f32 / len,
                    damaged: r.covered_by(&damage) as f32 / len,
                    findings: density.get(&(i as u64)).copied().unwrap_or(0),
                    volume: volumes.iter().find(|v| v.range.contains(r.start())).map(|v| v.index),
                    content: None,
                }
            })
            .collect();
        Ok(Self { disk_len, cell_len, cells: out })
    }

    /// Fill each cell's dominant content class from `index` (same disk; cells are cut the
    /// same way). Cells the index knows nothing about stay `None`.
    pub(crate) fn with_index(mut self, index: Option<&DiskIndex>) -> Self {
        let Some(index) = index.filter(|i| i.disk_len() == self.disk_len) else { return self };
        let content = index.cells(ByteRange::new(0, self.disk_len), self.cells.len());
        for (cell, c) in self.cells.iter_mut().zip(content) {
            cell.content = Some(c.dominant()).filter(|d| *d != BlockClass::Unscanned);
        }
        self
    }
}
