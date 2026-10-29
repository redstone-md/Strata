//! Segment files: signatures and the `.E01 → .E99 → .EAA … .ZZZ` naming scheme.

use std::fs::File;
use std::path::{Path, PathBuf};
use strata_kernel::{Error, Result};

const EVF1: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
const LVF1: &[u8; 8] = b"LVF\x09\x0d\x0a\xff\x00";
const EVF2: &[u8; 4] = b"EVF2";
const LEF2: &[u8; 4] = b"LEF2";

/// Accept EWF v1 disk images; explain everything else in the family.
pub(super) fn check_signature(head: &[u8]) -> Result<()> {
    if head.starts_with(EVF1) {
        Ok(())
    } else if head.starts_with(EVF2) || head.starts_with(LEF2) {
        Err(Error::format("EWF2 (.Ex01/.Lx01) not supported yet"))
    } else if head.starts_with(LVF1) {
        Err(Error::format("EWF logical evidence (.L01) holds files, not a disk image"))
    } else {
        Err(Error::format("not an EWF image"))
    }
}

pub(super) struct SegmentFile {
    file: File,
    len: u64,
}

impl SegmentFile {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

/// All existing segments of the set `path` belongs to, in order. Anything that does not follow
/// the naming scheme is a single-segment image.
pub(super) fn segment_paths(path: &Path) -> Vec<PathBuf> {
    let Some(letter) = path.extension().and_then(|e| e.to_str()).and_then(series_letter) else {
        return vec![path.to_path_buf()];
    };
    let parts: Vec<PathBuf> = (1..)
        .map_while(|n| extension(letter, n))
        .map(|ext| path.with_extension(ext))
        .take_while(|p| p.exists())
        .collect();
    if parts.is_empty() { vec![path.to_path_buf()] } else { parts }
}

/// `E01`, `e17`, `s01`, `EAB` → the series letter (`E`, `e`, `s`, `E`).
fn series_letter(ext: &str) -> Option<char> {
    let mut chars = ext.chars();
    let first = chars.next().filter(char::is_ascii_alphabetic)?;
    let rest: Vec<char> = chars.collect();
    let numbered = rest.len() == 2 && rest.iter().all(char::is_ascii_digit);
    let lettered = rest.len() == 2 && rest.iter().all(char::is_ascii_alphabetic);
    (numbered || lettered).then_some(first)
}

/// Extension of segment `n` (1-based): `E01`..`E99`, then `EAA`..`EZZ`, `FAA`..`ZZZ`.
fn extension(letter: char, n: u32) -> Option<String> {
    if n == 0 {
        return None;
    }
    if n <= 99 {
        return Some(format!("{letter}{n:02}"));
    }
    let base = if letter.is_ascii_lowercase() { b'a' } else { b'A' };
    let k = n - 100;
    let first = u32::from(letter as u8) + k / 676;
    if first > u32::from(base + 25) {
        return None;
    }
    let mid = base + (k / 26 % 26) as u8;
    let last = base + (k % 26) as u8;
    Some(format!("{}{}{}", char::from(first as u8), char::from(mid), char::from(last)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_follow_encase_order() {
        assert_eq!(extension('E', 1).as_deref(), Some("E01"));
        assert_eq!(extension('E', 99).as_deref(), Some("E99"));
        assert_eq!(extension('E', 100).as_deref(), Some("EAA"));
        assert_eq!(extension('E', 101).as_deref(), Some("EAB"));
        assert_eq!(extension('E', 775).as_deref(), Some("EZZ"));
        assert_eq!(extension('E', 776).as_deref(), Some("FAA"));
        assert_eq!(extension('s', 100).as_deref(), Some("saa"));
        assert_eq!(extension('Z', 776), None);
    }

    #[test]
    fn signatures() {
        assert!(check_signature(EVF1).is_ok());
        let err = check_signature(b"EVF2\r\n\x81\x00").unwrap_err().to_string();
        assert!(err.contains("EWF2 (.Ex01/.Lx01) not supported yet"), "{err}");
        assert!(check_signature(LVF1).is_err());
        assert!(check_signature(b"").is_err());
        assert_eq!(series_letter("E01"), Some('E'));
        assert_eq!(series_letter("e05"), Some('e'));
        assert_eq!(series_letter("E1"), None);
        // `.img` matches the lettered shape; discovery then finds no `.i01` and keeps the file.
        assert_eq!(segment_paths(Path::new("no/such/disk.img")), vec![PathBuf::from("no/such/disk.img")]);
        assert_eq!(series_letter("Ex01"), None);
    }
}
