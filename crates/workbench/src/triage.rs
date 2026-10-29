//! False-positive triage: findings inside live operating-system and program files are
//! almost always byte patterns that merely look like keys (class names in `rt.jar`,
//! API names in DLLs, stop-word lists). They stay visible but drop in confidence.

use strata_case::Case;
use strata_kernel::{EvidenceId, Result};

/// Path prefixes (lower case, `/`-separated) of installed system and program files.
const SYSTEM_PREFIXES: &[&str] = &["windows/", "winnt/", "program files/", "program files (x86)/", "programdata/microsoft/", "i386/", "$orphans/$"];

/// Extensions of binaries, fonts and linguistic data that never hold user keys.
const SYSTEM_EXTENSIONS: &[&str] = &[
    "dll", "exe", "sys", "ocx", "cpl", "drv", "mui", "jar", "class", "ttf", "ttc", "fon", "otf", "nls", "chs", "cht",
    "lex", "dic", "msi", "msp", "cab", "cat", "manifest", "pnf", "inf", "chm", "hlp",
];

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
        self.case.downgrade_system_hits(id, SYSTEM_PREFIXES, SYSTEM_EXTENSIONS, SYSTEM_FACTOR)
    }
}
