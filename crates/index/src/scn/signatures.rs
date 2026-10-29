//! File-type element stream (`TF/4` groups): every file start R-Studio's signature search
//! found. The payloads of all `TF/4` groups form one byte stream (entries cross group
//! boundaries). Each entry:
//!
//! ```text
//! u8   flags     0x60 always set; bits 0-1 select the sector field width (3, 4, 5, 8 bytes),
//!                bits 2-3 the size field width (2, 3, 4, 8 bytes); 0x80 = details follow
//! u8   group     R-Studio's file-type group (documents, images, executables...)
//! uN   sector    start sector (absolute, disk sector size)
//! uN   size      file size in bytes as R-Studio estimated it
//! [4]  tag       file type, stored backwards (`GPJ\0` = JPG, `ATXT` = TXTA)
//! u16  type id   R-Studio's internal type number
//! if flags & 0x80:
//!   u8 mask, then per set bit: 0x01 u32 time stamp, 0x02 u16 width u16 height u16 depth,
//!   0x04 u16, 0x08 8 bytes, 0x10 string (u8 len+1, u8 kind, len bytes)
//! ```
//! Masks with other bits are not decoded: the decoder skips forward to the next valid entry
//! and counts the skipped bytes.

use serde::Serialize;
use strata_kernel::bytes::uint_le_var;

const SECTOR_WIDTH: [usize; 4] = [3, 4, 5, 8];
const SIZE_WIDTH: [usize; 4] = [2, 3, 4, 8];
const HAS_DETAILS: u8 = 0x80;
const KNOWN_MASK: u8 = 0x1F;
const FIELD_LEN: [(u8, usize); 4] = [(0x01, 4), (0x02, 6), (0x04, 2), (0x08, 8)];
const STRING: u8 = 0x10;

/// One file start (or text run) found by R-Studio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScnRegion {
    pub offset: u64,
    pub len: u64,
    /// Readable tag, e.g. `*b"\0JPG"`, `*b"TXTA"`.
    pub tag: [u8; 4],
}

impl ScnRegion {
    /// Tag without padding, e.g. `JPG`.
    pub fn tag_name(&self) -> String {
        String::from_utf8_lossy(&self.tag).trim_matches(['\0', ' ']).to_string()
    }

    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len)
    }
}

/// Decoded stream plus how many bytes could not be read as entries.
#[derive(Debug, Default)]
pub(crate) struct Decoded {
    pub regions: Vec<ScnRegion>,
    pub entries: u64,
    pub skipped_bytes: u64,
}

pub(crate) struct StreamDecoder {
    sector_size: u64,
    disk_len: Option<u64>,
}

impl StreamDecoder {
    pub fn new(sector_size: u64, disk_len: Option<u64>) -> Self {
        Self { sector_size: sector_size.max(1), disk_len }
    }

    /// Decode the whole stream. Exact repeats and runs of one tag that touch or overlap
    /// (text found in consecutive pieces) are merged, which keeps text-heavy disks small.
    pub fn decode(&self, stream: &[u8]) -> Decoded {
        let mut out = Decoded::default();
        let mut pos = 0;
        while pos < stream.len() {
            match self.entry(stream, pos) {
                Some((region, next)) => {
                    out.entries += 1;
                    push_merged(&mut out.regions, region);
                    pos = next;
                }
                None => {
                    out.skipped_bytes += 1;
                    pos += 1;
                }
            }
        }
        out
    }

    fn entry(&self, s: &[u8], pos: usize) -> Option<(ScnRegion, usize)> {
        let flags = *s.get(pos)?;
        if flags & 0x70 != 0x60 || *s.get(pos + 1)? > 0x0F {
            return None;
        }
        let sector_w = SECTOR_WIDTH[usize::from(flags & 3)];
        let size_w = SIZE_WIDTH[usize::from((flags >> 2) & 3)];
        let mut at = pos + 2;
        let sector = uint_le_var(s, at, sector_w)?;
        at += sector_w;
        let len = uint_le_var(s, at, size_w)?;
        at += size_w;
        let stored: [u8; 4] = s.get(at..at + 4)?.try_into().ok()?;
        if !stored.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b' ' | 0)) {
            return None;
        }
        at += 4 + 2;
        if flags & HAS_DETAILS != 0 {
            at = Self::skip_details(s, at)?;
        }
        if at > s.len() {
            return None;
        }
        let offset = sector.checked_mul(self.sector_size)?;
        if self.disk_len.is_some_and(|d| offset >= d) {
            return None;
        }
        let tag = [stored[3], stored[2], stored[1], stored[0]];
        Some((ScnRegion { offset, len, tag }, at))
    }

    fn skip_details(s: &[u8], mut at: usize) -> Option<usize> {
        let mask = *s.get(at)?;
        if mask & !KNOWN_MASK != 0 {
            return None;
        }
        at += 1;
        for (bit, len) in FIELD_LEN {
            if mask & bit != 0 {
                at += len;
            }
        }
        if mask & STRING != 0 {
            let len = usize::from(*s.get(at)?);
            at += 2 + len.saturating_sub(1);
        }
        Some(at)
    }
}

fn push_merged(regions: &mut Vec<ScnRegion>, r: ScnRegion) {
    if let Some(last) = regions.last_mut()
        && last.tag == r.tag
        && r.offset >= last.offset
        && r.offset <= last.end()
        && (is_text(r.tag) || r.offset == last.offset)
    {
        last.len = last.end().max(r.end()) - last.offset;
        return;
    }
    regions.push(r);
}

/// Text runs: R-Studio's plain ANSI / Unicode text detections.
pub(crate) fn is_text(tag: [u8; 4]) -> bool {
    &tag == b"TXTA" || &tag == b"TXTU"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scn::testkit::FileTypeEntry;

    #[test]
    fn decodes_every_width_and_detail_shape() {
        let entries = [
            FileTypeEntry::new(0x1F3, 0x200, *b"TXTA"),
            FileTypeEntry::new(0x1F4, 0x300, *b"TXTA"),
            FileTypeEntry::new(0x0001_0217, 0x2B0F, *b"\0JPG").details(0x03, None),
            FileTypeEntry::new(0x0001_0217, 0x2B0F, *b"\0JPG").details(0x03, None),
            FileTypeEntry::new(0x0403_0201, 0x0006_9B20, *b"PEDL").details(0x11, Some("name.dll")),
            FileTypeEntry::new(0x01_0203_0405, 0x0001_0000_0000, *b"ZIP\0").details(0x1F, Some("x")),
            FileTypeEntry::new(9, 1, *b"TXTU"),
        ];
        let stream: Vec<u8> = entries.iter().flat_map(|e| e.encode()).collect();
        let d = StreamDecoder::new(512, None).decode(&stream);
        assert_eq!((d.entries, d.skipped_bytes), (7, 0));
        let tags: Vec<String> = d.regions.iter().map(|r| r.tag_name()).collect();
        assert_eq!(tags, ["TXTA", "JPG", "PEDL", "ZIP", "TXTU"], "text pieces and repeats merged");
        assert_eq!(d.regions[0], ScnRegion { offset: 0x1F3 * 512, len: 0x500, tag: *b"TXTA" });
        assert_eq!(d.regions[3].offset, 0x01_0203_0405 * 512);
        assert_eq!(d.regions[3].len, 0x0001_0000_0000);
    }

    #[test]
    fn skips_undecodable_entries_and_resumes() {
        let good = FileTypeEntry::new(100, 10, *b"\0PNG").encode();
        let mut bad = FileTypeEntry::new(200, 10, *b"\0GIF").details(0x40, None).encode();
        bad.extend_from_slice(&[0xAB; 5]);
        let stream: Vec<u8> = [good.clone(), bad.clone(), good].concat();
        let d = StreamDecoder::new(512, None).decode(&stream);
        assert_eq!(d.regions.len(), 1, "both PNG entries are the same start");
        assert_eq!(d.entries, 2);
        assert_eq!(d.skipped_bytes, bad.len() as u64);
        assert!(StreamDecoder::new(512, Some(100 * 512)).decode(&FileTypeEntry::new(100, 1, *b"\0PNG").encode()).regions.is_empty());
    }
}
