//! Where findings lie: most of them outside any listed file means the data that held them
//! lost its file entries (deleted, formatted over, or a file table Strata could not read).

use super::Check;
use crate::inputs::DiskInputs;
use crate::observation::{Observation, Severity, Signal};
use crate::units::{count, percent, share};

/// Findings needed before their placement means anything.
const MIN_FINDINGS: u64 = 200;
/// Share outside files that is worth a warning.
const OUTSIDE_SHARE: f64 = 0.7;

pub(crate) struct FreeSpaceCheck;

impl Check for FreeSpaceCheck {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>) {
        let h = disk.hits;
        let total = h.total();
        if total < MIN_FINDINGS || share(h.free, total) < OUTSIDE_SHARE {
            return;
        }
        out.push(
            Observation::new(
                Severity::Warning,
                Signal::FindingsOutsideFiles,
                format!("{} of findings lie outside any file", percent(h.free, total)),
                "Most keys, seeds, addresses and identities were found in free space rather than in listed files. The files \
                 that held them were deleted and their entries reused, the disk was formatted, or its file table was not \
                 fully read. Carving and the free-space findings are the main source here.",
            )
            .figure("Outside files", count(h.free))
            .figure("In deleted files", count(h.deleted))
            .figure("In live files", count(h.live)),
        );
    }
}
