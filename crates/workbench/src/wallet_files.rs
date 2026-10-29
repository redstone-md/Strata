//! File-level wallet analysis: parse whole wallet files found by the filesystem walk,
//! including deleted and orphaned ones, so keys come with labels, encryption state and a
//! crack hash instead of loose byte hits.

use strata_case::{Attribution, Case, FileRef};
use strata_fs::{ExtentReader, FileEntry};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, EvidenceId, Result};

/// Wallet files are small; anything bigger is not a wallet worth parsing whole.
const MAX_WALLET_BYTES: u64 = 256 << 20;

pub struct WalletFileAnalyzer<'a> {
    case: &'a Case,
}

impl<'a> WalletFileAnalyzer<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Name-based preselection; content is then confirmed by the parser itself.
    fn is_candidate(e: &FileEntry) -> bool {
        if e.is_dir || e.size == 0 || e.size > MAX_WALLET_BYTES {
            return false;
        }
        let name = e.name.to_ascii_lowercase();
        let path = e.path.to_ascii_lowercase();
        name.contains("wallet")
            || name.ends_with(".key")
            || name.ends_with(".dat") && (path.contains("bitcoin") || path.contains("litecoin"))
            || path.contains("electrum") && path.contains("wallets")
            || path.contains("multibit")
            || path.contains("armory")
    }

    pub fn run(&self, id: EvidenceId) -> Result<usize> {
        let source = self.case.source(id)?;
        let layout = self.case.layout(id)?;
        let mut found = Vec::new();
        for (vol, fs) in layout.filesystems() {
            let vol_source = vol.open(source.clone());
            for e in fs.entries().iter().filter(|e| Self::is_candidate(e)) {
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
        self.case.store_hits(id, &found)?;
        Ok(found.len())
    }
}
