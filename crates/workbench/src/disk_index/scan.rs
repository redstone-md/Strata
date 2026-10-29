//! Building the index during the deep scan: prepare a builder (resumed or seeded index plus
//! ownership and damage), save snapshots with the scan watermark while it runs, then flag
//! findings and save the result.

use super::IndexService;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_engine::{ScanControl, ScanSummary, Scanner};
use strata_index::{DEFAULT_BLOCK_SIZE, DiskIndex, IndexBuilder};
use strata_kernel::{ByteRange, EvidenceId, Result};

/// How often a running scan persists the index.
const SAVE_EVERY: Duration = Duration::from_secs(15);

impl IndexService<'_> {
    /// Index to continue for `id`: the stored one when it matches the disk, else a new one.
    /// Ownership and unreadable ranges are (re)applied from the current layout.
    pub fn prepare(&self, id: EvidenceId) -> Result<Arc<IndexBuilder>> {
        let source = self.case.source(id)?;
        let len = source.len();
        let mut index = match self.load(id) {
            Some(i) if i.disk_len() == len && i.block_size() == DEFAULT_BLOCK_SIZE => (*i).clone(),
            _ => DiskIndex::new(len, DEFAULT_BLOCK_SIZE),
        };
        let layout = self.case.layout(id)?;
        index.apply_ownership(&super::ownership::spans(&layout, &self.case.record(id)?.volumes, len));
        index.mark_unreadable(&source.damage());
        Ok(Arc::new(IndexBuilder::new(index)))
    }

    /// Run `scan` (the case's deep scan with `builder` attached as observer) while saving
    /// the index every few seconds, then finish it. A stored scan resume point beyond what the
    /// index covers (the app stopped between two saves) is filled first by an observer-only
    /// pass over just that gap.
    pub fn run_scan(
        &self,
        id: EvidenceId,
        builder: &Arc<IndexBuilder>,
        control: &ScanControl,
        scan: impl FnOnce() -> Result<ScanSummary>,
    ) -> Result<ScanSummary> {
        let covered = builder.snapshot(0).scanned_to();
        if let Some((mark, _, false)) = self.case.scan_state(id)?
            && mark > covered
        {
            let gap = ByteRange::from_bounds(covered, mark);
            let source = self.case.source(id)?;
            Scanner::new(Vec::new()).with_observer(builder.clone()).run(source.as_ref(), gap, &ScanControl::default(), |_| {})?;
            self.save(id, &builder.snapshot(mark))?;
        }
        let done = std::sync::atomic::AtomicBool::new(false);
        let result = std::thread::scope(|s| {
            s.spawn(|| {
                let mut last = Instant::now();
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    if last.elapsed() >= SAVE_EVERY {
                        let _ = self.save(id, &builder.snapshot(control.snapshot().watermark));
                        last = Instant::now();
                    }
                }
            });
            let r = scan();
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            r
        });
        let mut index = builder.snapshot(control.snapshot().watermark);
        let block = u64::from(index.block_size());
        let density = self.case.finding_density(id, block)?;
        index.mark_findings(density.keys().map(|b| b * block));
        self.save(id, &index)?;
        result
    }
}
