//! Carve files out of unallocated space and look inside them for wallets.
//!
//! Free space is processed in pieces of at most `every_bytes`: file starts (from the disk
//! index of a complete scan when it kept every signature there, else from a signature pass
//! over just that piece), carving and wallet parsing of the pieces since the last checkpoint
//! commit together with the position reached. Carved files stay bounded by their whole free
//! range and the end of the last carved file is carried over, so pieces give exactly the
//! files of one pass.

use super::sweep::{SweepPos, scan_piece};
use crate::Workbench;
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

#[derive(Debug, Default, Serialize, Deserialize)]
struct CarveCursor {
    #[serde(flatten)]
    pos: SweepPos,
    /// End of the last carved file: signatures before it lie inside that file.
    covered_until: u64,
    bytes: u64,
    carved: usize,
    wallets: usize,
}

impl Cursor for CarveCursor {
    fn note(&self) -> String {
        match self.pos.offset {
            0 => format!("free range {} ({} files carved so far)", self.pos.range + 1, self.carved),
            at => format!("free range {} at 0x{at:X} ({} files carved so far)", self.pos.range + 1, self.carved),
        }
    }
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

pub(super) fn run(ctx: &StepContext<'_>, wb: &Workbench) -> Result<String> {
    let id = ctx.evidence();
    // The scanner counts what it reads; the carver reads through the job's counter.
    let source = ctx.case().source(id)?;
    let layout = ctx.case().layout(id)?;
    let ranges = layout.free_space(source.len());
    let mut cur: CarveCursor = ctx.cursor().unwrap_or_default();
    ctx.control().begin_at(cur.bytes, ranges.iter().map(|r| r.len()).sum());
    let scanner = Scanner::new(vec![Arc::new(SignatureDetector::new())]);
    let carver = Carver::new(ctx.source()?);
    let index = wb.index();
    let piece = ctx.policy().every_bytes.max(1 << 20);
    let mut pending: Vec<(Hit, Attribution)> = Vec::new();
    let (mut indexed, mut read) = (0u64, 0u64);
    while let Some((range, start, end)) = cur.pos.next(&ranges, piece) {
        let mut signatures = match index.signatures_for(id, &[ByteRange::from_bounds(start, end)]) {
            Some(hits) => {
                ctx.control().items_done(end - start);
                indexed += end - start;
                hits.into_iter().filter(|h| h.offset >= start && h.offset < end).collect()
            }
            None => {
                read += end - start;
                scan_piece(&scanner, source.as_ref(), range, (start, end), ctx.control())?
            }
        };
        if ctx.should_stop() {
            break;
        }
        signatures.retain(|h| h.offset >= cur.covered_until);
        signatures.sort_by_key(|h| h.offset);
        ctx.current(&format!("carving 0x{start:X}–0x{end:X}"));
        let carved = carver.carve_ranges(&[range], &signatures);
        let (hits, wallets) = findings(&carver, &layout, &carved);
        pending.extend(hits);
        cur.covered_until = carved.iter().map(|f| f.range.end()).fold(cur.covered_until, u64::max);
        cur.pos.advance(range, end);
        cur.bytes += end - start;
        cur.carved += carved.len();
        cur.wallets += wallets;
        if !carved.is_empty() {
            ctx.log(format!(
                "{} carved from 0x{start:X}–0x{end:X}, {}",
                super::count(carved.len(), "file", "files"),
                super::count(wallets, "wallet", "wallets")
            ));
        }
        if ctx.tick(1) || end - start >= piece {
            let batch = std::mem::take(&mut pending);
            ctx.commit(&cur, |w| w.hits(id, &batch))?;
        }
    }
    let batch = std::mem::take(&mut pending);
    ctx.commit(&cur, |w| w.hits(id, &batch))?;
    if indexed > 0 {
        ctx.log(format!("file starts of {indexed} bytes taken from the disk index, {read} bytes read again"));
    }
    Ok(format!("{} files carved, {} wallets", cur.carved, cur.wallets))
}
