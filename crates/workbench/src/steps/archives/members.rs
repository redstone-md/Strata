//! Everything learned from one unpacked member: byte-detector findings, wallets parsed
//! whole, renamed extensions, encrypted members — attributed to `archive!/member`.

use super::targets::Target;
use std::sync::Arc;
use strata_archive::Member;
use strata_case::{ArchiveMemberRow, Attribution, FileRef};
use strata_identify::Category;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory};

/// Members scanned per detector call; consecutive chunks overlap by the longest match.
const CHUNK: usize = 16 << 20;
/// Wallet files are small; bigger members are not parsed whole.
const MAX_WALLET_BYTES: usize = 256 << 20;
/// Confidence of a wallet file with no keys, addresses or encrypted content.
const EMPTY_WALLET_CONFIDENCE: f32 = 0.1;

pub(crate) struct MemberAnalyzer {
    detectors: Vec<Arc<dyn Detector>>,
    overlap: usize,
}

impl MemberAnalyzer {
    pub fn new(detectors: Vec<Arc<dyn Detector>>) -> Self {
        let overlap = detectors.iter().map(|d| d.max_match()).max().unwrap_or(0);
        Self { detectors, overlap }
    }

    /// Findings of one member (offsets are member offsets) and its listing row.
    pub fn analyze(&self, archive: &Target, m: &Member<'_>) -> (Vec<(Hit, Attribution)>, ArchiveMemberRow) {
        let mut found = Vec::new();
        // An opened nested archive is compressed data; its members are analysed instead.
        if !m.unpacked && !m.bytes.is_empty() {
            found.extend(self.scan(m.bytes));
            found.extend(Self::wallet(m));
            found.extend(Self::renamed(m));
        }
        if m.bytes.is_empty() && m.entry.encrypted {
            found.push(
                Hit::new("archive.encrypted", HitCategory::FileSignature, 0, 0)
                    .label(format!("encrypted archive member ({})", m.format.name()))
                    .value(m.path.to_string())
                    .confidence(Confidence::MEDIUM),
            );
        }
        let hits = found.into_iter().map(|h| Self::attribute(archive, m, h)).collect();
        (hits, Self::row(archive, m))
    }

    fn scan(&self, bytes: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        let step = CHUNK.saturating_sub(self.overlap).max(1);
        let mut start = 0;
        loop {
            let end = (start + CHUNK).min(bytes.len());
            let last = end == bytes.len();
            let mut chunk_hits = Vec::new();
            for d in &self.detectors {
                d.scan(&bytes[start..end], start as u64, &mut chunk_hits);
            }
            let tail = (start + step) as u64;
            hits.extend(chunk_hits.into_iter().filter(|h| last || h.offset < tail));
            if last {
                return hits;
            }
            start += step;
        }
    }

    fn wallet(m: &Member<'_>) -> Option<Hit> {
        if m.bytes.len() > MAX_WALLET_BYTES {
            return None;
        }
        let report = strata_crypto::analyze_wallet(m.bytes)?;
        // A wallet-shaped file with nothing inside (an empty MultiBit stub, a template) is
        // kept for the record but stays below the noise floor.
        let empty = report.keys().is_empty() && report.addresses().is_empty() && report.encrypted() != Some(true);
        Some(
            Hit::new("wallet.archive", HitCategory::Wallet, 0, m.bytes.len())
                .label(format!(
                    "{} wallet in archive{}",
                    report.kind().name(),
                    if report.encrypted() == Some(true) { " (encrypted)" } else { "" }
                ))
                .value(format!("{} keys, {} addresses", report.keys().len(), report.addresses().len()))
                .confidence(if empty { Confidence::new(EMPTY_WALLET_CONFIDENCE) } else { Confidence::CERTAIN })
                .details(report.to_json()),
        )
    }

    /// Valuable content under a mundane name inside the archive (a ZIP saved as `.jpg`).
    fn renamed(m: &Member<'_>) -> Option<Hit> {
        let v = m.verdict?;
        let mismatch = v.extension_mismatch.as_ref().filter(|x| x.suspicious && v.category != Category::Executable)?;
        let confidence = if v.confidence.get() > Confidence::MEDIUM.get() { v.confidence } else { Confidence::MEDIUM };
        Some(
            Hit::new("identify.mismatch", HitCategory::FileSignature, 0, m.bytes.len().min(1 << 20))
                .label(format!("{} disguised as .{}", v.type_name, mismatch.declared))
                .value(m.path.to_string())
                .confidence(confidence)
                .details(serde_json::to_value(v).unwrap_or_default()),
        )
    }

    /// Hits keep the archive's evidence offset; the member offset goes to the file reference.
    fn attribute(archive: &Target, m: &Member<'_>, mut hit: Hit) -> (Hit, Attribution) {
        let member_offset = hit.offset;
        hit.offset = archive.offset;
        let mut details = match std::mem::take(&mut hit.details) {
            serde_json::Value::Object(o) => o,
            serde_json::Value::Null => serde_json::Map::new(),
            other => serde_json::Map::from_iter([("detail".to_string(), other)]),
        };
        details.insert("archive_chain".into(), serde_json::json!(m.chain));
        details.insert("member_offset".into(), serde_json::json!(member_offset));
        hit.details = serde_json::Value::Object(details);
        let file = FileRef { path: m.path.to_string(), state: archive.state, file_offset: member_offset };
        (hit, Attribution { volume: archive.volume, file: Some(file) })
    }

    fn row(archive: &Target, m: &Member<'_>) -> ArchiveMemberRow {
        let notes: Vec<&str> = m.damage.iter().map(|d| d.note()).collect();
        ArchiveMemberRow {
            archive_path: archive.name.clone(),
            member_path: m.path.to_string(),
            depth: m.depth as u32,
            size: m.entry.size,
            packed: m.entry.packed,
            recovered: m.bytes.len() as u64,
            encrypted: m.entry.encrypted,
            detected_type: m.verdict.map(|v| v.type_name.clone()),
            extension_mismatch: m.verdict.is_some_and(|v| v.extension_mismatch.is_some()),
            modified: m.entry.mtime.map(|t| t.unix_secs()),
            damage: serde_json::to_string(&notes).unwrap_or_default(),
        }
    }
}
