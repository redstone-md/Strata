//! Content-based type of every file: catches renamed extensions (a wallet saved as `.jpg`)
//! and tells what damaged files still are.

use strata_case::{Attribution, Case, FileRef};
use strata_engine::ScanControl;
use strata_fs::ExtentReader;
use strata_identify::Identifier;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, EvidenceId, Result};

/// Head bytes read per file; enough for headers, directories and structure probes.
const HEAD_BYTES: usize = 1 << 20;

/// Extensions of plain user documents: random bytes behind these are worth a look
/// (encrypted containers, wallets saved as text files). Random bytes behind media or
/// binaries are normal compression or overwritten clusters.
const PLAIN_DOCUMENTS: &[&str] = &["txt", "doc", "rtf", "csv", "ini", "log", "xml", "htm", "html", "dat", "bak"];

pub struct FileClassifier<'a> {
    case: &'a Case,
}

impl<'a> FileClassifier<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Content we read may not be the file's own: deleted files whose clusters were reused,
    /// or extents over unreadable sectors. Such files and headerless random data behind
    /// media/binary extensions produced ~1,400 false alarms on a 40 GB test disk.
    fn worth_reporting(e: &strata_fs::FileEntry, v: &strata_identify::TypeVerdict) -> bool {
        if !e.damage.is_empty() {
            return false;
        }
        // Hidden valuables are wallets, databases, archives, documents, mail — not programs.
        if v.category == strata_identify::Category::Executable {
            return false;
        }
        let path = e.path.to_ascii_lowercase();
        let in_system = ["windows/", "winnt/", "program files/", "program files (x86)/"].iter().any(|p| path.starts_with(p));
        if in_system && !matches!(v.category, strata_identify::Category::Wallet | strata_identify::Category::Database) {
            return false;
        }
        if v.method == strata_identify::Method::Entropy {
            let ext = e.extension().unwrap_or_default().to_ascii_lowercase();
            return e.state == strata_fs::EntryState::Allocated && PLAIN_DOCUMENTS.contains(&ext.as_str());
        }
        true
    }

    /// Returns `(files classified, suspicious mismatches)`.
    pub fn run(&self, id: EvidenceId, control: &ScanControl) -> Result<(usize, usize)> {
        let source = self.case.source(id)?;
        let layout = self.case.layout(id)?;
        let identifier = Identifier::new();
        let total: usize = layout.filesystems().map(|(_, fs)| fs.entries().iter().filter(|e| !e.is_dir).count()).sum();
        control.begin_items(total as u64);
        let (mut rows, mut flagged) = (Vec::new(), Vec::new());
        for (vol, fs) in layout.filesystems() {
            let vol_source = vol.open(source.clone());
            for (idx, e) in fs.entries().iter().enumerate().filter(|(_, e)| !e.is_dir) {
                if control.is_cancelled() {
                    break;
                }
                control.item_done();
                if e.size == 0 {
                    continue;
                }
                let Ok(head) = ExtentReader::new(vol_source.as_ref(), e).read_all(HEAD_BYTES) else { continue };
                let v = identifier.identify(&head, Some(&e.name));
                let mismatch = v.extension_mismatch.as_ref();
                let notes = mismatch.map(|m| m.reason.clone()).unwrap_or_default();
                if let Some(m) = mismatch.filter(|m| m.suspicious && Self::worth_reporting(e, &v)) {
                    let offset = vol.range.start() + e.extents.first().and_then(|x| x.volume_offset).unwrap_or(0);
                    let confidence = if v.confidence.get() > Confidence::MEDIUM.get() { v.confidence } else { Confidence::MEDIUM };
                    let hit = Hit::new("identify.mismatch", HitCategory::FileSignature, offset, head.len())
                        .label(format!("{} disguised as .{}", v.type_name, m.declared))
                        .value(e.path.clone())
                        .confidence(confidence)
                        .details(serde_json::to_value(&v).unwrap_or_default());
                    let file = FileRef { path: e.path.clone(), state: e.state, file_offset: 0 };
                    flagged.push((hit, Attribution { volume: Some(vol.index), file: Some(file) }));
                }
                rows.push((vol.index, idx, v.type_name.clone(), mismatch.is_some(), notes));
            }
        }
        self.case.set_file_types(id, &rows)?;
        self.case.store_hits(id, &flagged)?;
        Ok((rows.len(), flagged.len()))
    }
}
