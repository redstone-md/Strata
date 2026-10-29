//! File-level wallet analysis: parse whole wallet files found by the filesystem walk,
//! including deleted and orphaned ones, so keys come with labels, encryption state and a
//! crack hash instead of loose byte hits.

use crate::jobs::context::StepContext;
use strata_case::{Attribution, FileRef};
use strata_fs::{ExtentReader, FileEntry};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Result};

/// Wallet files are small; anything bigger is not a wallet worth parsing whole.
const MAX_WALLET_BYTES: u64 = 256 << 20;

pub(super) struct WalletFileAnalyzer<'a, 'c> {
    ctx: &'a StepContext<'c>,
}

impl<'a, 'c> WalletFileAnalyzer<'a, 'c> {
    pub fn new(ctx: &'a StepContext<'c>) -> Self {
        Self { ctx }
    }

    /// Name-based preselection; content is then confirmed by the parser itself.
    fn is_candidate(e: &FileEntry) -> bool {
        if e.is_dir || e.size == 0 || e.size > MAX_WALLET_BYTES {
            return false;
        }
        strata_crypto::WalletFileName::is_parse_candidate(&e.path, &e.name)
    }

    /// Wallet files of the evidence, parsed whole, as findings to store.
    pub fn find(&self) -> Result<Vec<(Hit, Attribution)>> {
        let source = self.ctx.source()?;
        let layout = self.ctx.case().layout(self.ctx.evidence())?;
        let mut found = Vec::new();
        for (vol, fs) in layout.filesystems() {
            let vol_source = vol.open(source.clone());
            for e in fs.entries().iter().filter(|e| Self::is_candidate(e)) {
                if self.ctx.should_stop() {
                    break;
                }
                self.ctx.current(&e.path);
                let Ok(bytes) = ExtentReader::new(vol_source.as_ref(), e).read_all(MAX_WALLET_BYTES as usize) else {
                    continue;
                };
                let Some(report) = strata_crypto::analyze_wallet(&bytes) else { continue };
                let first_extent = e.extents.first().and_then(|x| x.volume_offset).unwrap_or(0);
                let hit = Hit::new("wallet.file", HitCategory::Wallet, vol.range.start() + first_extent, bytes.len())
                    .label(format!(
                        "{} wallet{}",
                        report.kind().name(),
                        if report.encrypted() == Some(true) { " (encrypted)" } else { "" }
                    ))
                    .value(format!("{} keys, {} addresses", report.keys().len(), report.addresses().len()))
                    .confidence(Confidence::CERTAIN)
                    .details(report.to_json());
                let attribution = Attribution {
                    volume: Some(vol.index),
                    file: Some(FileRef { path: e.path.clone(), state: e.state, file_offset: 0 }),
                };
                found.push((hit, attribution));
            }
        }
        Ok(found)
    }
}
