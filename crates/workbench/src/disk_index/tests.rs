//! Incremental persistence: an interrupted scan leaves a partial index that the resumed scan
//! completes, also when the index file is older than the scan's resume point.

use super::{IndexCache, IndexService};
use std::sync::Arc;
use strata_case::Case;
use strata_engine::{ChunkObserver, ScanControl, Scanner};
use strata_index::DiskIndex;
use strata_kernel::EvidenceId;

const MIB: usize = 1 << 20;

/// Cancels the scan once it has seen a chunk at or beyond `at`.
struct StopAt {
    control: Arc<ScanControl>,
    at: u64,
}

impl ChunkObserver for StopAt {
    fn observe(&self, _data: &[u8], base: u64, _owned: usize) {
        if base >= self.at {
            self.control.cancel();
        }
    }
}

fn disk() -> Vec<u8> {
    let mut d = vec![0u8; 12 * MIB];
    for (i, b) in d.iter_mut().enumerate().skip(MIB).step_by(3) {
        *b = (i % 251) as u8;
    }
    d[5 * MIB..6 * MIB].fill(b'a');
    d
}

fn scan(case: &Case, cache: &IndexCache, id: EvidenceId, stop_at: Option<u64>) -> bool {
    let service = IndexService::new(case, cache);
    let control = Arc::new(ScanControl::default());
    let builder = service.prepare(id).unwrap();
    let mut scanner = Scanner::new(Vec::new()).with_chunk_size(MIB).with_workers(2).with_observer(builder.clone());
    if let Some(at) = stop_at {
        scanner = scanner.with_observer(Arc::new(StopAt { control: control.clone(), at }));
    }
    let summary = service.run_scan(id, &builder, &control, || case.scan(id, &scanner, &control)).unwrap();
    summary.completed
}

fn setup() -> (tempfile::TempDir, Case, EvidenceId) {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("disk.img");
    std::fs::write(&img, disk()).unwrap();
    let case = Case::open(&dir.path().join("t.strata")).unwrap();
    let id = case.add_evidence(&img.display().to_string()).unwrap().id;
    (dir, case, id)
}

fn reference() -> DiskIndex {
    let (_dir, case, id) = setup();
    let cache = IndexCache::default();
    assert!(scan(&case, &cache, id, None));
    (*IndexService::new(&case, &cache).load(id).unwrap()).clone()
}

#[test]
fn resumed_scan_completes_the_index() {
    let (_dir, case, id) = setup();
    let cache = IndexCache::default();
    assert!(!scan(&case, &cache, id, Some(4 * MIB as u64)));
    let partial = IndexService::new(&case, &cache).load(id).unwrap();
    let (mark, _, done) = case.scan_state(id).unwrap().unwrap();
    assert!(!done && mark >= 4 * MIB as u64 && mark < 12 * MIB as u64);
    assert_eq!(partial.scanned_to(), mark, "index saved with the scan watermark");
    assert!(scan(&case, &cache, id, None));
    let full = IndexService::new(&case, &cache).load(id).unwrap();
    assert!(full.is_complete());
    assert_eq!(full.records(), reference().records());
}

#[test]
fn a_gap_behind_the_resume_point_is_filled() {
    let (dir, case, id) = setup();
    let cache = IndexCache::default();
    assert!(!scan(&case, &cache, id, Some(6 * MIB as u64)));
    // The app died before the index was saved: only the case knows how far the scan got.
    std::fs::remove_file(dir.path().join("t.strata").join("cache").join(format!("index-{id}.sidx"))).unwrap();
    assert!(scan(&case, &cache, id, None));
    let full = IndexService::new(&case, &cache).load(id).unwrap();
    assert!(full.is_complete());
    assert_eq!(full.records(), reference().records());
}
