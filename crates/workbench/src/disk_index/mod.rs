//! Disk index use cases: build it during the deep scan, seed it from an R-Studio scan file,
//! persist it in the case cache, and serve it to the sector map, carving and search.

mod import;
mod ownership;
mod scan;
#[cfg(test)]
mod tests;

pub use import::ScnImport;

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use strata_case::Case;
use strata_index::{BlockClass, CellContent, DiskIndex, EntrySource, IndexFile, IndexStats, Provenance};
use strata_kernel::scan::Hit;
use strata_kernel::{ByteRange, EvidenceId, Result};

/// Summary and per-cell content of one evidence item's index, for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct DiskIndexView {
    pub stats: IndexStats,
    pub provenance: Provenance,
    pub cell_len: u64,
    pub cells: Vec<CellContent>,
    /// Consecutive cells with the same dominant class: `(class, cells)`.
    pub runs: Vec<(BlockClass, u32)>,
}

/// Loaded indexes, reloaded when the file on disk changes (the scan saves periodically).
#[derive(Default)]
pub(crate) struct IndexCache {
    loaded: Mutex<HashMap<EvidenceId, (SystemTime, Arc<DiskIndex>)>>,
}

pub(crate) struct IndexService<'a> {
    case: &'a Case,
    cache: &'a IndexCache,
}

impl<'a> IndexService<'a> {
    pub fn new(case: &'a Case, cache: &'a IndexCache) -> Self {
        Self { case, cache }
    }

    fn path(&self, id: EvidenceId) -> PathBuf {
        self.case.root().join("cache").join(format!("index-{id}.sidx"))
    }

    /// The stored index, if any. A file that cannot be read is treated as absent (the next
    /// scan rebuilds it).
    pub fn load(&self, id: EvidenceId) -> Option<Arc<DiskIndex>> {
        let path = self.path(id);
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
        if let Some((at, idx)) = self.cache.loaded.lock().get(&id)
            && *at == modified
        {
            return Some(idx.clone());
        }
        let (idx, _damage) = IndexFile::load(&path).ok().flatten()?;
        let idx = Arc::new(idx);
        self.cache.loaded.lock().insert(id, (modified, idx.clone()));
        Some(idx)
    }

    pub fn save(&self, id: EvidenceId, index: &DiskIndex) -> Result<()> {
        IndexFile::save(index, &self.path(id))?;
        self.cache.loaded.lock().remove(&id);
        Ok(())
    }

    pub fn view(&self, id: EvidenceId, cells: usize) -> Option<DiskIndexView> {
        let idx = self.load(id)?;
        let cells = cells.max(1);
        let content = idx.cells(ByteRange::new(0, idx.disk_len()), cells);
        let mut runs: Vec<(BlockClass, u32)> = Vec::new();
        for c in &content {
            match runs.last_mut() {
                Some((class, n)) if *class == c.dominant() => *n += 1,
                _ => runs.push((c.dominant(), 1)),
            }
        }
        Some(DiskIndexView {
            stats: idx.stats(),
            provenance: idx.provenance().clone(),
            cell_len: idx.disk_len().div_ceil(cells as u64).max(1),
            cells: content,
            runs,
        })
    }

    /// Signature hits of our own complete pass inside `ranges`, in the detector's hit form;
    /// `None` when no complete index exists (the caller then runs its own pass).
    pub fn signatures_for(&self, id: EvidenceId, ranges: &[ByteRange]) -> Option<Vec<Hit>> {
        let idx = self.load(id).filter(|i| i.is_complete() && i.keeps_signatures_in(ranges))?;
        Some(idx.signatures_in(ranges, EntrySource::Scan).into_iter().map(|h| h.to_detector_hit()).collect())
    }
}
