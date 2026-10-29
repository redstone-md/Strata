//! False-positive triage: findings inside live operating-system and program files are
//! almost always byte patterns that merely look like keys (class names in `rt.jar`,
//! API names in DLLs, stop-word lists). They stay visible but drop in confidence.

use strata_case::Case;
use strata_kernel::{EvidenceId, Result};

/// Confidence multiplier for findings inside system files.
const SYSTEM_FACTOR: f32 = 0.2;
/// A raw hex value seen this often is a library constant, not a saved key.
const CONSTANT_COPIES: u32 = 20;
/// Key-like findings in a file named like a key backup are shown at least at this confidence.
const WALLET_FILE_FLOOR: f32 = 0.4;
/// A file with this many different e-mail addresses is a list (dump, customer table).
const ADDRESS_LIST: u32 = 1000;

pub struct Triage<'a> {
    case: &'a Case,
}

impl<'a> Triage<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Returns the number of findings downgraded.
    pub fn run(&self, id: EvidenceId) -> Result<usize> {
        let system = self.case.downgrade_system_hits(id, SYSTEM_FACTOR)?;
        let constants = self.case.downgrade_repeated_constants(id, CONSTANT_COPIES, SYSTEM_FACTOR)?;
        let lists = self.case.downgrade_address_lists(id, ADDRESS_LIST, SYSTEM_FACTOR)?;
        self.case.promote_wallet_named_files(id, WALLET_FILE_FLOOR)?;
        Ok(system + constants + lists)
    }
}
