//! False-positive triage: findings inside live operating-system and program files are
//! almost always byte patterns that merely look like keys (class names in `rt.jar`,
//! API names in DLLs, stop-word lists). They stay visible but drop in confidence.

use strata_case::Case;
use strata_kernel::{EvidenceId, Result};

/// Path prefixes (lower case, `/`-separated) of installed system and program files.
const SYSTEM_PREFIXES: &[&str] = &["windows/", "winnt/", "program files/", "program files (x86)/", "programdata/microsoft/", "i386/", "$orphans/$"];

/// Linux system folders (lower case), matched anywhere in the path so copies under
/// container layers (`var/lib/docker/overlay2/<id>/diff/usr/...`) and chroots count too:
/// package lists and documentation repeat maintainer e-mails hundreds of thousands of times.
const SYSTEM_FOLDERS: &[&str] = &[
    "usr/share/", "usr/lib/", "usr/lib32/", "usr/lib64/", "usr/include/", "usr/src/", "usr/bin/", "usr/sbin/",
    "lib/modules/", "lib/firmware/", "var/lib/dpkg/", "var/lib/apt/lists/", "var/cache/apt/", "var/lib/rpm/",
    "var/lib/snapd/", "snap/core", "boot/",
];

/// Extensions of binaries, fonts and linguistic data that never hold user keys.
const SYSTEM_EXTENSIONS: &[&str] = &[
    "dll", "exe", "sys", "ocx", "cpl", "drv", "mui", "jar", "class", "ttf", "ttc", "fon", "otf", "nls", "chs", "cht",
    "lex", "dic", "msi", "msp", "cab", "cat", "manifest", "pnf", "inf", "chm", "hlp", "so", "ko", "pm", "pyc", "mo",
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
        self.case.downgrade_system_hits(id, SYSTEM_PREFIXES, SYSTEM_FOLDERS, SYSTEM_EXTENSIONS, SYSTEM_FACTOR)
    }
}
