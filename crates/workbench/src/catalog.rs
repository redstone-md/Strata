use std::sync::Arc;
use strata_kernel::scan::Detector;

/// Every byte-level detector Strata ships, assembled in one place.
pub struct DetectorCatalog;

impl DetectorCatalog {
    pub fn all() -> Vec<Arc<dyn Detector>> {
        let mut out = Vec::new();
        out.extend(strata_crypto::detectors().into_iter().map(Arc::from));
        out.extend(strata_accounts::detectors());
        out.push(Arc::new(strata_volume::PartitionDetector));
        out
    }
}
