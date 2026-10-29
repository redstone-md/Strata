//! Wallet trails: where each wallet-relevant file of the case went, rebuilt on request from
//! what the case holds (a few seconds on a large case, so callers run it off the UI thread).

use strata_kernel::{Period, Result};
use strata_leads::Lead;
use strata_trails::{Fate, Trail, TrailBuilder};

/// Trails below this score stay out of the lead list (they remain on the trails screen).
const LEAD_MIN_SCORE: f32 = 40.0;

/// All trails of a case, best first.
pub(crate) fn build(case: &strata_case::Case) -> Result<Vec<Trail>> {
    Ok(TrailBuilder::new().build(&case.trail_inputs()?))
}

/// Trails worth ranking among the leads: not plainly live, and scored high enough.
pub(crate) fn leads(trails: &[Trail]) -> Vec<Lead> {
    trails.iter().filter(|t| t.verdict.fate != Fate::Live && t.score >= LEAD_MIN_SCORE).map(Trail::to_lead).collect()
}

impl crate::Workbench {
    /// Wallet trails whose dates touch `period` (undated ones always), best first.
    pub fn wallet_trails(&self, period: Period) -> Result<Vec<Trail>> {
        let mut trails = build(self.case())?;
        trails.retain(|t| period.overlaps(t.window.map(|w| w.0), t.window.map(|w| w.1)));
        Ok(trails)
    }
}
