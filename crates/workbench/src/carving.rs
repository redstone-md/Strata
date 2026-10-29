//! Carve files out of unallocated space and look inside them for wallets.

use std::sync::Arc;
use strata_carve::{Carver, carve_ranges};
use strata_case::Case;
use strata_engine::{ScanControl, Scanner};
use strata_identify::{Category, SignatureDetector};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{ByteRange, Confidence, EvidenceId, Result};

/// Carved wallets/databases larger than this are not parsed whole.
const MAX_PARSE_BYTES: usize = 256 << 20;

pub struct UnallocatedCarver<'a> {
    case: &'a Case,
}

impl<'a> UnallocatedCarver<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Free space of every parsed filesystem plus disk space outside all parsed volumes.
    fn free_ranges(&self, id: EvidenceId, disk_len: u64) -> Result<Vec<ByteRange>> {
        let layout = self.case.layout(id)?;
        let mut ranges: Vec<ByteRange> = layout
            .filesystems()
            .flat_map(|(vol, fs)| fs.unallocated().into_iter().map(move |r| r.shifted(vol.range.start())))
            .collect();
        let mut covered: Vec<ByteRange> = layout.filesystems().map(|(v, _)| v.range).collect();
        covered.sort();
        let mut cursor = 0;
        for c in covered.iter().chain(std::iter::once(&ByteRange::new(disk_len, 0))) {
            if c.start() > cursor {
                ranges.push(ByteRange::from_bounds(cursor, c.start()));
            }
            cursor = cursor.max(c.end());
        }
        Ok(ByteRange::coalesce(ranges))
    }

    /// Returns `(files carved, wallets inside them)`.
    pub fn run(&self, id: EvidenceId, control: &ScanControl) -> Result<(usize, usize)> {
        let source = self.case.source(id)?;
        let layout = self.case.layout(id)?;
        let ranges = self.free_ranges(id, source.len())?;
        let scanner = Scanner::new(vec![Arc::new(SignatureDetector::new())]);
        let mut signatures: Vec<Hit> = Vec::new();
        scanner.run_ranges(source.as_ref(), &ranges, control, |h| signatures.extend(h))?;
        if control.is_cancelled() {
            return Ok((0, 0));
        }
        signatures.sort_by_key(|h| h.offset);
        let carved = carve_ranges(source.clone(), &ranges, &signatures);
        let carver = Carver::new(source.clone());
        let mut hits = Vec::new();
        let mut wallets = 0;
        for f in &carved {
            let v = &f.verdict;
            let keep = matches!(
                v.category,
                Category::Wallet | Category::Database | Category::Archive | Category::Document | Category::Mail
            );
            if !keep {
                continue;
            }
            let carved_hit = Hit::new("carve.unallocated", HitCategory::FileSignature, f.range.start(), f.range.len() as usize)
                .label(format!("carved {}", v.type_name))
                .value(format!("{}@{:#x}+{}", v.type_name, f.range.start(), f.range.len()))
                .confidence(v.confidence)
                .details(serde_json::json!({ "range": f.range, "length": f.length, "verdict": v, "damage": f.damage }));
            hits.push((carved_hit, layout.attribute(f.range.start())));
            if matches!(v.category, Category::Wallet | Category::Database) {
                let Ok(bytes) = carver.read(f, MAX_PARSE_BYTES) else { continue };
                if let Some(report) = strata_crypto::analyze_wallet(&bytes) {
                    wallets += 1;
                    let hit = Hit::new("wallet.carved", HitCategory::Wallet, f.range.start(), bytes.len())
                        .label(format!("{} wallet (carved)", report.kind().name()))
                        .value(format!("{} keys, {} addresses", report.keys().len(), report.addresses().len()))
                        .confidence(Confidence::HIGH)
                        .details(report.to_json());
                    hits.push((hit, layout.attribute(f.range.start())));
                }
            }
        }
        self.case.store_hits(id, &hits)?;
        Ok((carved.len(), wallets))
    }
}
