use crate::{ChunkObserver, ScanControl};
use crossbeam_channel::bounded;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_kernel::scan::{Detector, Hit};
use strata_kernel::{ByteRange, Error, Result};
use strata_source::BlockSource;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub range: ByteRange,
    pub scanned: u64,
    pub hits: u64,
    pub completed: bool,
    pub elapsed_secs: f64,
}

struct Chunk {
    /// Absolute offset of the chunk's first byte.
    base: u64,
    /// Bytes owned by this chunk; anything after is overlap borrowed from the next chunk.
    owned: usize,
    data: Vec<u8>,
}

/// Streams a source once and runs every detector on every chunk.
pub struct Scanner {
    detectors: Vec<Arc<dyn Detector>>,
    observers: Vec<Arc<dyn ChunkObserver>>,
    chunk_size: usize,
    workers: usize,
}

impl Scanner {
    /// Default worker count: evidence is read at disk speed (≈100–200 MB/s) and all detectors
    /// together sustain ≈150 MB/s per core, so a few workers keep up without hogging the CPU.
    pub const DEFAULT_WORKERS: usize = 3;

    pub fn new(detectors: Vec<Arc<dyn Detector>>) -> Self {
        let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
        Self { detectors, observers: Vec::new(), chunk_size: 16 << 20, workers: Self::DEFAULT_WORKERS.min(cores.saturating_sub(1)).max(1) }
    }

    pub fn with_chunk_size(mut self, bytes: usize) -> Self {
        self.chunk_size = bytes.max(4096);
        self
    }

    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Also hand every chunk to `observer` (no hits, no extra read). Observers do not take part
    /// in [`Self::detector_ids`], so adding one does not invalidate a stored resume point.
    pub fn with_observer(mut self, observer: Arc<dyn ChunkObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    pub fn detector_ids(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    fn overlap(&self) -> usize {
        let detectors = self.detectors.iter().map(|d| d.max_match());
        detectors.chain(self.observers.iter().map(|o| o.lookahead())).max().unwrap_or(0)
    }

    /// Scan `range` of `source`. `on_hits` is called from the collector thread with each
    /// chunk's hits (already de-duplicated against chunk overlap), in no particular order.
    pub fn run(
        &self,
        source: &dyn BlockSource,
        range: ByteRange,
        control: &ScanControl,
        on_hits: impl FnMut(Vec<Hit>) + Send,
    ) -> Result<ScanSummary> {
        let range = range.intersect(&ByteRange::new(0, source.len())).unwrap_or(ByteRange::new(range.start(), 0));
        control.begin(range.start(), range.len());
        self.run_range(source, range, control, on_hits)
    }

    /// Scan several ranges (e.g. unallocated space) as one job. Progress counts bytes over all
    /// ranges; the watermark is not meaningful for resuming.
    pub fn run_ranges(
        &self,
        source: &dyn BlockSource,
        ranges: &[ByteRange],
        control: &ScanControl,
        mut on_hits: impl FnMut(Vec<Hit>) + Send,
    ) -> Result<ScanSummary> {
        let bounds = ByteRange::new(0, source.len());
        let ranges: Vec<ByteRange> = ByteRange::coalesce(ranges.iter().filter_map(|r| r.intersect(&bounds)).collect());
        let total = ranges.iter().map(|r| r.len()).sum();
        control.begin(0, total);
        let started = std::time::Instant::now();
        for r in &ranges {
            if control.is_cancelled() {
                break;
            }
            self.run_range(source, *r, control, &mut on_hits)?;
        }
        let snap = control.snapshot();
        Ok(ScanSummary {
            range: ByteRange::new(0, total),
            scanned: snap.scanned,
            hits: snap.hits,
            completed: !control.is_cancelled(),
            elapsed_secs: started.elapsed().as_secs_f64(),
        })
    }

    fn run_range(
        &self,
        source: &dyn BlockSource,
        range: ByteRange,
        control: &ScanControl,
        mut on_hits: impl FnMut(Vec<Hit>) + Send,
    ) -> Result<ScanSummary> {
        let started = std::time::Instant::now();
        let overlap = self.overlap();
        let (chunk_tx, chunk_rx) = bounded::<Chunk>(self.workers * 2);
        let (hit_tx, hit_rx) = bounded::<(u64, u64, Vec<Hit>)>(self.workers * 2);

        let read_result = std::thread::scope(|scope| {
            for _ in 0..self.workers {
                let rx = chunk_rx.clone();
                let tx = hit_tx.clone();
                scope.spawn(move || {
                    crate::priority::lower_current_thread();
                    for chunk in rx {
                        let hits = self.scan_chunk(&chunk);
                        let end = chunk.base + chunk.owned as u64;
                        if tx.send((chunk.base, end, hits)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(hit_tx);
            let collector = scope.spawn(move || {
                for (start, end, hits) in hit_rx {
                    control.add_hits(hits.len() as u64);
                    if !hits.is_empty() {
                        on_hits(hits);
                    }
                    control.chunk_done(start, end);
                }
            });
            let result = self.read_loop(source, range, overlap, control, &chunk_tx);
            drop(chunk_tx);
            let _ = collector.join();
            result
        });
        read_result?;
        let snap = control.snapshot();
        Ok(ScanSummary {
            range,
            scanned: snap.scanned,
            hits: snap.hits,
            completed: !control.is_cancelled() && snap.watermark >= range.end(),
            elapsed_secs: started.elapsed().as_secs_f64(),
        })
    }

    fn read_loop(
        &self,
        source: &dyn BlockSource,
        range: ByteRange,
        overlap: usize,
        control: &ScanControl,
        tx: &crossbeam_channel::Sender<Chunk>,
    ) -> Result<()> {
        let mut pos = range.start();
        while pos < range.end() {
            if control.is_cancelled() {
                return Ok(());
            }
            let owned = ((range.end() - pos) as usize).min(self.chunk_size);
            let tail = ((range.end() - pos - owned as u64) as usize).min(overlap);
            let mut data = vec![0u8; owned + tail];
            let n = source.read_at(pos, &mut data)?;
            data.truncate(n);
            if tx.send(Chunk { base: pos, owned: owned.min(n), data }).is_err() {
                return Err(Error::Other("scan workers stopped".into()));
            }
            if n == 0 {
                break;
            }
            pos += owned as u64;
        }
        Ok(())
    }

    fn scan_chunk(&self, chunk: &Chunk) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        for d in &self.detectors {
            d.scan(&chunk.data, chunk.base, &mut hits);
        }
        for o in &self.observers {
            o.observe(&chunk.data, chunk.base, chunk.owned);
        }
        let limit = chunk.base + chunk.owned as u64;
        hits.retain(|h| h.offset < limit);
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::scan::{HitCategory, HitSink};
    use strata_source::{SourceInfo, SourceKind};

    struct Mem(Vec<u8>);
    impl BlockSource for Mem {
        fn info(&self) -> SourceInfo {
            SourceInfo { kind: SourceKind::RawImage, label: "m".into(), location: "m".into(), len: self.len(), sector_size: 512 }
        }
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let s = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - s);
            buf[..n].copy_from_slice(&self.0[s..s + n]);
            Ok(n)
        }
        fn damage(&self) -> Vec<ByteRange> {
            Vec::new()
        }
    }

    struct Needle;
    impl Detector for Needle {
        fn id(&self) -> &'static str {
            "test.needle"
        }
        fn max_match(&self) -> usize {
            6
        }
        fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
            for (i, w) in chunk.windows(6).enumerate() {
                if w == b"NEEDLE" {
                    sink.emit(Hit::new(self.id(), HitCategory::Marker, base + i as u64, 6));
                }
            }
        }
    }

    /// Records which offsets each observed chunk owned.
    #[derive(Default)]
    struct Owned(parking_lot::Mutex<Vec<(u64, u64, usize)>>);
    impl ChunkObserver for Owned {
        fn lookahead(&self) -> usize {
            100
        }
        fn observe(&self, data: &[u8], base: u64, owned: usize) {
            self.0.lock().push((base, base + owned as u64, data.len() - owned));
        }
    }

    #[test]
    fn observers_see_every_owned_byte_once_with_lookahead() {
        let observer = Arc::new(Owned::default());
        let scanner = Scanner::new(Vec::new()).with_chunk_size(4096).with_workers(2).with_observer(observer.clone());
        let control = ScanControl::default();
        scanner.run(&Mem(vec![1u8; 10_000]), ByteRange::new(0, 10_000), &control, |_| {}).unwrap();
        let mut seen = observer.0.lock().clone();
        seen.sort();
        let spans: Vec<(u64, u64)> = seen.iter().map(|s| (s.0, s.1)).collect();
        assert_eq!(spans, vec![(0, 4096), (4096, 8192), (8192, 10_000)]);
        assert_eq!(seen.iter().map(|s| s.2).collect::<Vec<_>>(), vec![100, 100, 0]);
        assert!(scanner.detector_ids().is_empty());
    }

    #[test]
    fn finds_matches_across_chunk_boundaries_exactly_once() {
        let mut data = vec![0u8; 100_000];
        let spots = [0usize, 4093, 4096 - 3, 8190, 50_000, 99_994];
        for s in spots {
            data[s..s + 6].copy_from_slice(b"NEEDLE");
        }
        let scanner = Scanner::new(vec![Arc::new(Needle)]).with_chunk_size(4096).with_workers(3);
        let control = ScanControl::default();
        let mut found = Vec::new();
        let summary = scanner
            .run(&Mem(data), ByteRange::new(0, 100_000), &control, |h| found.extend(h.into_iter().map(|h| h.offset)))
            .unwrap();
        found.sort();
        let mut expected: Vec<u64> = spots.iter().map(|s| *s as u64).collect();
        expected.sort();
        expected.dedup();
        assert_eq!(found, expected);
        assert!(summary.completed);
        assert_eq!(control.snapshot().watermark, 100_000);
    }
}
