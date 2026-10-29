//! Carve files out of unallocated space and look inside them for wallets.
//!
//! Free space is processed in batches of whole ranges: signature pass, carving and wallet
//! parsing of a batch commit together with the count of ranges done. Carved files never
//! cross a range end, so batching gives the same files as one pass.

use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_carve::{CarvedFile, Carver};
use strata_case::{Attribution, EvidenceLayout};
use strata_engine::Scanner;
use strata_identify::{Category, SignatureDetector};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{ByteRange, Confidence, Result};

/// Carved wallets/databases larger than this are not parsed whole.
const MAX_PARSE_BYTES: usize = 256 << 20;
/// Free space processed per commit (whole ranges, so a batch may be larger).
const BATCH_BYTES: u64 = 256 << 20;

#[derive(Debug, Default, Serialize, Deserialize)]
struct CarveCursor {
    /// Free ranges (coalesced, in disk order) finished.
    ranges: usize,
    bytes: u64,
    carved: usize,
    wallets: usize,
}

impl Cursor for CarveCursor {
    fn note(&self) -> String {
        format!("free range {} ({} files carved so far)", self.ranges + 1, self.carved)
    }
}

/// Free space of every parsed filesystem plus disk space outside all parsed volumes.
fn free_ranges(layout: &EvidenceLayout, disk_len: u64) -> Vec<ByteRange> {
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
    ByteRange::coalesce(ranges)
}

/// Findings for the carved files worth keeping, and the number of wallets among them.
fn findings(carver: &Carver, layout: &EvidenceLayout, carved: &[CarvedFile]) -> (Vec<(Hit, Attribution)>, usize) {
    let mut hits = Vec::new();
    let mut wallets = 0;
    for f in carved {
        let v = &f.verdict;
        let keep = matches!(v.category, Category::Wallet | Category::Database | Category::Archive | Category::Document | Category::Mail);
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
    (hits, wallets)
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let source = ctx.source()?;
    let layout = ctx.case().layout(id)?;
    let ranges = free_ranges(&layout, source.len());
    let mut cur: CarveCursor = ctx.cursor().unwrap_or_default();
    ctx.control().begin_at(cur.bytes, ranges.iter().map(|r| r.len()).sum());
    let scanner = Scanner::new(vec![Arc::new(SignatureDetector::new())]);
    let carver = Carver::new(source.clone());
    let max_ranges = ctx.policy().every_items.max(1) as usize;
    while cur.ranges < ranges.len() {
        let mut end = cur.ranges;
        let mut bytes = 0;
        while end < ranges.len() && bytes < BATCH_BYTES && end - cur.ranges < max_ranges {
            bytes += ranges[end].len();
            end += 1;
        }
        let batch = &ranges[cur.ranges..end];
        let mut signatures: Vec<Hit> = Vec::new();
        scanner.continue_ranges(source.as_ref(), batch, ctx.control(), |h| signatures.extend(h))?;
        if ctx.should_stop() {
            break;
        }
        signatures.sort_by_key(|h| h.offset);
        ctx.current(&format!("carving 0x{:X}–0x{:X}", batch[0].start(), batch[batch.len() - 1].end()));
        let carved = carver.carve_ranges(batch, &signatures);
        let (hits, wallets) = findings(&carver, &layout, &carved);
        cur.ranges = end;
        cur.bytes += bytes;
        cur.carved += carved.len();
        cur.wallets += wallets;
        ctx.commit(&cur, |w| w.hits(id, &hits))?;
        if !carved.is_empty() {
            ctx.log(format!("{} files carved in {} free ranges, {wallets} wallets", carved.len(), batch.len()));
        }
    }
    Ok(format!("{} files carved, {} wallets", cur.carved, cur.wallets))
}
