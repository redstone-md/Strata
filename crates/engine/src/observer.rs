//! Side channel for consumers that need every byte of the pass but produce no hits (the disk
//! index profiler). Observers run on the worker threads right after the detectors, on the same
//! chunk buffer, so they cost CPU but never an extra read.

/// Sees every chunk of a scan exactly once.
///
/// Unlike a [`strata_kernel::scan::Detector`], an observer is told which part of the buffer the
/// chunk owns: bytes in `data[owned..]` belong to the next chunk and are only there as context
/// (up to [`ChunkObserver::lookahead`] bytes). Anything keyed by position must only be recorded
/// for offsets inside `[base, base + owned)`, so nothing is counted twice.
pub trait ChunkObserver: Send + Sync {
    /// Context the observer needs past the owned region (e.g. its block size). The engine
    /// overlaps chunks by the largest of this and every detector's `max_match`.
    fn lookahead(&self) -> usize {
        0
    }

    /// Called once per chunk from a worker thread; `data[0]` sits at absolute offset `base`.
    fn observe(&self, data: &[u8], base: u64, owned: usize);
}
