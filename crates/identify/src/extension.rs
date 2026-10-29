//! Extension-mismatch reasoning: was the file renamed to hide what it is?

use crate::registry::{Category, FileType, Registry, TypeId};
use crate::verdict::ExtensionMismatch;
use strata_kernel::Confidence;

/// Extensions used by too many unrelated formats to contradict anything on their own.
const AMBIGUOUS: &[&str] = &[
    "dat", "bin", "tmp", "bak", "old", "000", "001", "part", "partial", "crdownload", "download",
    "sav", "dmp", "cache", "data", "raw", "file", "chk", "orig", "backup", "copy", "~",
];

/// Lower-cased extension of `name`; `Some("")` when it has none.
pub fn extension_of(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 12 => Some(ext.to_ascii_lowercase()),
        _ => Some(String::new()),
    }
}

fn is_textual(t: &FileType) -> bool {
    t.category == Category::Text || matches!(t.id, TypeId::Eml | TypeId::Mbox | TypeId::Rtf)
}

/// Does `ext` fit `actual` or a related type (family, or both textual)?
fn compatible(actual: &FileType, ext: &str) -> bool {
    if actual.has_extension(ext) {
        return true;
    }
    Registry::by_extension(ext).any(|t| actual.same_family(t.id) || (is_textual(actual) && is_textual(t)))
}

/// Categories a valuable file is typically disguised as.
fn mundane(ext: &str) -> bool {
    let mut owners = Registry::by_extension(ext).peekable();
    owners.peek().is_none()
        || owners.all(|t| {
            matches!(t.category, Category::Image | Category::Media | Category::Executable | Category::System | Category::Text)
        })
}

/// Compare the declared name with the detected type.
pub fn check(declared_name: Option<&str>, actual: TypeId, confidence: Confidence) -> Option<ExtensionMismatch> {
    let ext = extension_of(declared_name?)?;
    let spec = actual.spec();
    if actual == TypeId::Unknown || confidence.get() < 0.5 || compatible(spec, &ext) {
        return None;
    }
    // Text has countless extensions (.toml, .rs, .lock...): only registered ones can contradict it.
    if is_textual(spec) && Registry::by_extension(&ext).next().is_none() {
        return None;
    }
    let expected: Vec<String> = spec.extensions.iter().filter(|e| !e.is_empty()).map(|e| e.to_string()).collect();
    let make = |suspicious: bool, reason: String| {
        Some(ExtensionMismatch { declared: ext.clone(), actual, expected: expected.clone(), suspicious, reason })
    };
    if actual == TypeId::EncryptedOrRandom {
        // Random bytes behind an extension whose format always has a header.
        let claims_header = Registry::by_extension(&ext).any(|t| !t.magics.is_empty());
        return (claims_header && !ext.is_empty() && !AMBIGUOUS.contains(&ext.as_str())).then(|| {
            ExtensionMismatch {
                declared: ext.clone(),
                actual,
                expected: Vec::new(),
                suspicious: true,
                reason: format!(".{ext} file has no {ext} header and random content: possible encrypted container"),
            }
        });
    }
    if ext.is_empty() {
        return spec
            .category
            .is_valuable()
            .then(|| format!("{} stored without an extension", spec.name))
            .and_then(|r| make(false, r));
    }
    if AMBIGUOUS.contains(&ext.as_str()) {
        return (confidence.get() >= 0.8 && spec.category.is_valuable())
            .then(|| format!(".{ext} is generic; content is {}", spec.name))
            .and_then(|r| make(false, r));
    }
    let disguised_value = spec.category.is_valuable() && mundane(&ext);
    let disguised_code = spec.category == Category::Executable
        && Registry::by_extension(&ext).all(|t| matches!(t.category, Category::Image | Category::Text | Category::Media | Category::Document));
    let suspicious = disguised_value || disguised_code;
    let reason = if suspicious {
        format!("{} disguised with a .{ext} extension", spec.name)
    } else {
        format!(".{ext} does not match detected {}", spec.name)
    };
    make(suspicious, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HIGH: Confidence = Confidence::HIGH;

    #[test]
    fn families_are_not_mismatches() {
        assert!(check(Some("report.docx"), TypeId::Zip, HIGH).is_none());
        assert!(check(Some("a.zip"), TypeId::Docx, HIGH).is_none());
        assert!(check(Some("lib.jar"), TypeId::Zip, HIGH).is_none());
        assert!(check(Some("wallet.dat"), TypeId::BitcoinCoreBdb, HIGH).is_none());
        assert!(check(Some("notes.txt"), TypeId::Json, HIGH).is_none());
        assert!(check(Some("x.dll"), TypeId::Exe, HIGH).is_none());
        assert!(check(Some("Cargo.lock"), TypeId::Text, HIGH).is_none());
        assert!(check(Some("notes.jpg"), TypeId::Text, HIGH).is_some());
    }

    #[test]
    fn disguised_wallet_is_suspicious() {
        let m = check(Some("photo.jpg"), TypeId::BitcoinCoreBdb, HIGH).unwrap();
        assert!(m.suspicious);
        assert_eq!(m.declared, "jpg");
        let m = check(Some("C:\\Windows\\x.sys"), TypeId::SevenZip, HIGH).unwrap();
        assert!(m.suspicious);
    }

    #[test]
    fn ambiguous_only_when_confident() {
        assert!(check(Some("x.dat"), TypeId::Zip, Confidence::new(0.6)).is_none());
        let m = check(Some("x.dat"), TypeId::Zip, Confidence::new(0.9)).unwrap();
        assert!(!m.suspicious);
        assert!(check(Some("x.jpg"), TypeId::Zip, Confidence::LOW).is_none());
    }

    #[test]
    fn random_behind_header_format() {
        assert!(check(Some("holiday.avi"), TypeId::EncryptedOrRandom, Confidence::MEDIUM).unwrap().suspicious);
        assert!(check(Some("volume.tc"), TypeId::EncryptedOrRandom, Confidence::MEDIUM).is_none());
    }
}
