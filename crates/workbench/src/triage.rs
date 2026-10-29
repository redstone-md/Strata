//! False-positive triage: findings inside live operating-system and program files are
//! almost always byte patterns that merely look like keys (class names in `rt.jar`,
//! API names in DLLs, stop-word lists). They stay visible but drop in confidence.

use strata_case::Case;
use strata_kernel::{EvidenceId, Result};

/// Confidence multiplier for findings inside system files.
const SYSTEM_FACTOR: f32 = 0.2;

pub struct Triage<'a> {
    case: &'a Case,
}

impl<'a> Triage<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Returns the number of findings downgraded.
    pub fn run(&self, id: EvidenceId) -> Result<usize> {
        self.case.downgrade_system_hits(id, SYSTEM_FACTOR)
    }
}
