//! ZIP validation and refinement into OOXML / ODF / JAR / APK / EPUB by member names.

use super::{EntrySource, ZipArchive};
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use strata_kernel::Confidence;

/// Total uncompressed bytes we are willing to inflate for CRC checks during identification.
const VERIFY_BUDGET: u64 = 64 << 20;
/// Members listed individually in a verdict.
const LIST_LIMIT: usize = 2000;

/// Registry validator: buffer starts with a ZIP signature.
pub fn validate(data: &[u8]) -> Option<Probe> {
    analyze(data, Confidence::new(0.95))
}

/// Build a probe from whatever ZIP structure is in `data`; `base` is the confidence when the
/// structure is fully consistent.
pub fn analyze(data: &[u8], base: Confidence) -> Option<Probe> {
    let archive = ZipArchive::parse(data);
    if archive.entries().is_empty() {
        // An empty archive is just an end record.
        return (data.starts_with(b"PK\x05\x06") && data.len() >= 22).then(|| {
            let mut p = Probe::new(TypeId::Zip, base.scaled(0.8));
            p.note("empty archive");
            p.with_len(Some(22))
        });
    }
    let mut probe = Probe::new(refine(&archive, data), base).with_len(archive.declared_len());
    let entries = archive.entries();
    let mut budget = VERIFY_BUDGET;
    let mut ok = 0usize;
    for e in entries {
        let mut good = e.damage.is_empty() && e.data_start.is_some();
        let checkable = matches!(e.method, 0 | 8) && !e.is_dir() && !e.is_encrypted();
        if good && checkable && e.uncompressed_size <= budget {
            budget -= e.uncompressed_size;
            let ex = archive.extract(data, e, e.uncompressed_size as usize);
            good = ex.is_intact();
            probe.damage.extend(ex.damage);
        }
        ok += usize::from(good);
        probe.damage.extend(e.damage.iter().cloned());
    }
    probe.damage.extend(archive.damage().iter().cloned());
    probe = probe.with_structure(ratio(ok, entries.len()));
    match archive.source() {
        EntrySource::LocalHeaders => {
            probe.note(format!("central directory missing; {} members rebuilt from local headers", entries.len()));
            probe.confidence = probe.confidence.scaled(0.85);
        }
        EntrySource::Merged => probe.note("central directory damaged; merged with local headers"),
        _ => {}
    }
    if archive.is_zip64() {
        probe.note("zip64");
    }
    let encrypted = entries.iter().filter(|e| e.is_encrypted()).count();
    if encrypted > 0 {
        probe.note(format!("{encrypted} encrypted member(s)"));
    }
    for e in entries.iter().take(LIST_LIMIT) {
        probe.item(InnerKind::Member, e.name.clone(), Some(e.uncompressed_size));
    }
    if entries.len() > LIST_LIMIT {
        probe.note(format!("{} more members not listed", entries.len() - LIST_LIMIT));
    }
    Some(probe)
}

fn refine(archive: &ZipArchive, data: &[u8]) -> TypeId {
    let has = |name: &str| archive.find(name).is_some();
    let has_prefix = |p: &str| archive.entries().iter().any(|e| e.name.starts_with(p));
    if has("[Content_Types].xml") || has_prefix("_rels/") {
        if has_prefix("word/") {
            return TypeId::Docx;
        }
        if has_prefix("xl/") {
            return TypeId::Xlsx;
        }
        if has_prefix("ppt/") {
            return TypeId::Pptx;
        }
    }
    if let Some(m) = archive.find("mimetype") {
        let mime = archive.extract(data, m, 128).data;
        let mime = String::from_utf8_lossy(&mime);
        let id = match mime.trim() {
            "application/vnd.oasis.opendocument.text" => Some(TypeId::Odt),
            "application/vnd.oasis.opendocument.spreadsheet" => Some(TypeId::Ods),
            "application/vnd.oasis.opendocument.presentation" => Some(TypeId::Odp),
            "application/epub+zip" => Some(TypeId::Epub),
            _ => None,
        };
        if let Some(id) = id {
            return id;
        }
    }
    if has("AndroidManifest.xml") && (has("classes.dex") || has_prefix("META-INF/")) {
        return TypeId::Apk;
    }
    if has("META-INF/MANIFEST.MF") && archive.entries().iter().any(|e| e.name.ends_with(".class")) {
        return TypeId::Jar;
    }
    TypeId::Zip
}
