//! Case metadata (`header`/`header2`), stored hashes (`hash`/`digest`) and acquisition read
//! errors (`error2`).

use super::chunk::inflate;
use std::collections::BTreeMap;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{array, u32_le, utf16le};

const MAX_HEADER_TEXT: usize = 1 << 20;
const ERROR2_ENTRIES: usize = 520;

/// Header category keys → readable names. Unknown keys are kept as-is.
const HEADER_KEYS: &[(&str, &str)] = &[
    ("c", "case_number"),
    ("n", "evidence_number"),
    ("a", "description"),
    ("e", "examiner"),
    ("t", "notes"),
    ("av", "acquisition_software"),
    ("ov", "acquisition_os"),
    ("m", "acquired"),
    ("u", "system_date"),
    ("p", "password_hash"),
    ("r", "compression"),
    ("md", "model"),
    ("sn", "serial_number"),
    ("l", "device_label"),
    ("pid", "process_id"),
    ("ext", "extents"),
];

/// Decode a `header` (ASCII) or `header2` (UTF-16LE with BOM) section into a metadata map.
///
/// The text is a tab-separated table: a category line `main`, then a key line, then a value line.
pub(super) fn parse_header(section: &[u8]) -> Option<BTreeMap<String, String>> {
    let raw = inflate(section, MAX_HEADER_TEXT)?;
    let text = match raw.get(..2) {
        Some([0xFF, 0xFE]) => utf16le(raw.get(2..).unwrap_or_default()),
        _ => raw.iter().take_while(|b| **b != 0).map(|b| char::from(*b)).collect(),
    };
    let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let main = lines.iter().position(|l| l.trim() == "main")?;
    let (keys, values) = (lines.get(main + 1)?, lines.get(main + 2)?);
    let map: BTreeMap<String, String> = keys
        .split('\t')
        .zip(values.split('\t'))
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| (readable_key(k.trim()), readable_value(k.trim(), v.trim())))
        .collect();
    (!map.is_empty()).then_some(map)
}

fn readable_key(key: &str) -> String {
    HEADER_KEYS.iter().find(|(k, _)| *k == key).map_or(key, |(_, name)| name).to_string()
}

/// `header2` stores dates as Unix seconds; `header` already uses `YYYY M D h m s`.
fn readable_value(key: &str, value: &str) -> String {
    let date = matches!(key, "m" | "u");
    match value.parse::<i64>().ok().filter(|_| date).and_then(Timestamp::from_unix_secs) {
        Some(ts) => ts.to_string(),
        None => value.to_string(),
    }
}

/// Hashes the acquiring tool computed over the media and stored in the image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredHashes {
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
}

impl StoredHashes {
    pub fn md5(&self) -> Option<[u8; 16]> {
        self.md5
    }

    pub fn sha1(&self) -> Option<[u8; 20]> {
        self.sha1
    }

    /// `hash`: MD5 at 0. `digest`: MD5 at 0, SHA-1 at 16. All-zero values mean "not computed".
    pub(super) fn absorb(&mut self, kind: &str, data: &[u8]) {
        fn set<const N: usize>(slot: &mut Option<[u8; N]>, value: Option<[u8; N]>) {
            if let Some(v) = value.filter(|v| v.iter().any(|b| *b != 0)) {
                *slot = Some(v);
            }
        }
        match kind {
            "hash" => set(&mut self.md5, array(data, 0)),
            "digest" => {
                set(&mut self.md5, array(data, 0));
                set(&mut self.sha1, array(data, 16));
            }
            _ => {}
        }
    }
}

/// `error2`: `u32 count` | 512 pad | `u32 adler32` | `count × (u32 first sector, u32 sectors)`.
/// Returns `(first_sector, sector_count)` pairs.
pub(super) fn parse_error2(data: &[u8]) -> Vec<(u64, u64)> {
    let count = u32_le(data, 0).unwrap_or(0) as usize;
    let body = data.get(ERROR2_ENTRIES..).unwrap_or_default();
    body.chunks_exact(8)
        .take(count)
        .filter_map(|e| Some((u64::from(u32_le(e, 0)?), u64::from(u32_le(e, 4)?))))
        .filter(|(_, n)| *n > 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn header2_utf16_with_dates() {
        let text = "1\nmain\nc\tn\te\tm\tzz\nCASE-7\t1\tAndy\t1000000000\tx\n\n";
        let mut raw = vec![0xFF, 0xFE];
        raw.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let map = parse_header(&zlib(&raw)).unwrap();
        assert_eq!(map["case_number"], "CASE-7");
        assert_eq!(map["examiner"], "Andy");
        assert_eq!(map["acquired"], "2001-09-09 01:46:40");
        assert_eq!(map["zz"], "x");
    }

    #[test]
    fn ascii_header_and_garbage() {
        let map = parse_header(&zlib(b"1\r\nmain\r\nc\ta\r\n42\tlaptop\r\n")).unwrap();
        assert_eq!(map["description"], "laptop");
        assert!(parse_header(b"garbage").is_none());
        assert!(parse_header(&zlib(b"no table here")).is_none());
    }

    #[test]
    fn hashes_ignore_zero_digests() {
        let mut h = StoredHashes::default();
        h.absorb("hash", &[0u8; 80]);
        assert_eq!(h.md5(), None);
        let mut digest = vec![0xAA; 16];
        digest.extend([0xBB; 20]);
        h.absorb("digest", &digest);
        assert_eq!(h.md5(), Some([0xAA; 16]));
        assert_eq!(h.sha1(), Some([0xBB; 20]));
        h.absorb("digest", &[1, 2]);
        assert_eq!(h.sha1(), Some([0xBB; 20]));
    }
}
