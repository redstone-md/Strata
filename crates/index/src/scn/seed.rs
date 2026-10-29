//! Seeding a [`DiskIndex`] from a decoded scan file, before (or while) our own pass runs.

use super::ScnInfo;
use super::signatures::is_text;
use super::types::type_for_tag;
use crate::index::DiskIndex;
use crate::record::{BlockClass, BlockRecord, SIGNATURE, TextKind};
use crate::side::{EntrySource, SignatureHit};
use strata_kernel::ByteRange;

/// Confidence given to an R-Studio file start until our own detector confirms it.
const HINT_CONFIDENCE: f32 = 0.5;
/// Typical entropy of natural-language text (bits per byte), for seeded text blocks.
const TEXT_ENTROPY: f32 = 4.5;

impl ScnInfo {
    /// Add what the scan file knows to `index` (which must describe the same disk):
    /// file starts of mapped types become R-Studio signature hits, other starts only flag
    /// their block, text runs mark the blocks they fully cover as seeded Text (only where
    /// nothing is known yet), and boot records join the side table. `label` names the file in
    /// the index provenance.
    pub fn seed(&self, index: &mut DiskIndex, label: &str) {
        let mut hits = Vec::new();
        for r in &self.signature_regions {
            if is_text(r.tag) {
                let kind = if &r.tag == b"TXTU" { TextKind::Utf16 } else { TextKind::Ascii };
                let content = BlockRecord::content(BlockClass::Text, kind, TEXT_ENTROPY).seeded();
                for i in index.blocks_within(ByteRange::new(r.offset, r.len)) {
                    let rec = index.records()[i];
                    if rec.class() == BlockClass::Unscanned {
                        index.records_mut()[i] = rec.with_content_of(content);
                    }
                }
                continue;
            }
            match type_for_tag(r.tag) {
                Some(type_id) => hits.push(SignatureHit {
                    offset: r.offset,
                    match_len: 0,
                    type_id,
                    declared_len: (r.len > 0).then_some(r.len),
                    confidence: HINT_CONFIDENCE,
                    validated: false,
                    source: EntrySource::RStudio,
                }),
                None => {
                    if let Some(i) = index.block_of(r.offset) {
                        let rec = index.records()[i];
                        index.records_mut()[i] = rec.with_flags(SIGNATURE);
                    }
                }
            }
        }
        index.add_signatures(hits);
        index.add_boot_records(self.boot_records.iter().copied());
        let p = index.provenance_mut();
        if !p.seeded_from.iter().any(|s| s == label) {
            p.seeded_from.push(label.to_string());
        }
        p.external_scanned_to = p.external_scanned_to.max(self.metadata.scanned_to);
    }
}
