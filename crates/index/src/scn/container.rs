//! Outer framing of an R-Studio `.scn` file: a 128-byte header, then checksummed groups.
//!
//! ```text
//! header  0x00..0x70  fixed signature block (identical in every file seen)
//!         0x70        u32 format version (1)
//! group   u32 size (including this 16-byte header) | 4-byte tag | 4-byte sub | u32 CRC32(payload)
//! ```
//! Tags are stored as little-endian FourCCs, so they read backwards ("TONI", "OOGR"). Scan
//! element groups use the tag `HS\0\0` and put `u16 kind | 2-char element tag` in `sub`.

use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, DamageKind};

pub(crate) const HEADER_LEN: usize = 0x80;
const VERSION_AT: usize = 0x70;
const GROUP_HEADER: usize = 16;
/// How far a damaged file is searched for the next intact group.
const RESYNC_WINDOW: usize = 4 << 20;

pub(crate) const TAG_OBJECT: [u8; 4] = *b"TONI";
pub(crate) const TAG_SCANNED_OBJECT: [u8; 4] = *b"ESNI";
pub(crate) const TAG_PROGRESS: [u8; 4] = *b"OOGR";
pub(crate) const TAG_ELEMENTS: [u8; 4] = *b"HS\0\0";
const KNOWN_TAGS: [[u8; 4]; 4] = [TAG_OBJECT, TAG_SCANNED_OBJECT, TAG_PROGRESS, TAG_ELEMENTS];

/// One intact group.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Group<'a> {
    pub offset: usize,
    pub tag: [u8; 4],
    pub sub: [u8; 4],
    pub payload: &'a [u8],
}

impl Group<'_> {
    /// `(kind, element tag)` of an element group, e.g. `(4, *b"TF")`.
    pub fn element(&self) -> Option<(u16, [u8; 2])> {
        (self.tag == TAG_ELEMENTS).then(|| (u16::from_le_bytes([self.sub[0], self.sub[1]]), [self.sub[2], self.sub[3]]))
    }

    /// Readable name for statistics: `TONI`, `OOGR`, `TF/4`...
    pub fn name(&self) -> String {
        match self.element() {
            Some((kind, tag)) => format!("{}/{kind}", String::from_utf8_lossy(&tag)),
            None => String::from_utf8_lossy(&self.tag).trim_end_matches('\0').to_string(),
        }
    }
}

pub(crate) struct Container<'a> {
    pub version: u32,
    pub groups: Vec<Group<'a>>,
    pub damage: Vec<Damage>,
}

impl<'a> Container<'a> {
    /// `None` when the data does not start like a scan file (no header or no intact first
    /// group).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let version = u32_le(data, VERSION_AT)?;
        let first = group_at(data, HEADER_LEN).filter(|g| KNOWN_TAGS.contains(&g.tag))?;
        let mut out = Container { version, groups: vec![first], damage: Vec::new() };
        let mut pos = HEADER_LEN + GROUP_HEADER + first.payload.len();
        while pos < data.len() {
            if let Some(g) = group_at(data, pos) {
                pos += GROUP_HEADER + g.payload.len();
                out.groups.push(g);
                continue;
            }
            let Some(next) = resync(data, pos) else {
                out.damage.push(Damage::new(DamageKind::Corrupt, Some(range(pos, data.len())), "scan file: unreadable tail"));
                break;
            };
            out.damage.push(Damage::new(DamageKind::Corrupt, Some(range(pos, next)), "scan file: damaged group skipped"));
            pos = next;
        }
        Some(out)
    }
}

fn range(a: usize, b: usize) -> ByteRange {
    ByteRange::from_bounds(a as u64, b as u64)
}

/// An intact group at `pos`: sane size and matching CRC.
fn group_at(data: &[u8], pos: usize) -> Option<Group<'_>> {
    let size = u32_le(data, pos)? as usize;
    let payload = data.get(pos.checked_add(GROUP_HEADER)?..pos.checked_add(size)?)?;
    let crc = u32_le(data, pos + 12)?;
    if size < GROUP_HEADER || crc32fast::hash(payload) != crc {
        return None;
    }
    let tag = data.get(pos + 4..pos + 8)?.try_into().ok()?;
    let sub = data.get(pos + 8..pos + 12)?.try_into().ok()?;
    // Element sub-tags are printable; a stray match on garbage is rejected here.
    if tag == TAG_ELEMENTS && u16_le(data, pos + 8)? > 0xFF {
        return None;
    }
    Some(Group { offset: pos, tag, sub, payload })
}

/// Next offset after `pos` holding an intact group with a known tag.
fn resync(data: &[u8], pos: usize) -> Option<usize> {
    let end = data.len().min(pos.saturating_add(RESYNC_WINDOW));
    (pos + 1..end).find(|&p| p >= 4 && data.get(p + 4..p + 8).is_some_and(|t| KNOWN_TAGS.iter().any(|k| k == t)) && group_at(data, p).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scn::testkit::ScnWriter;

    #[test]
    fn walks_groups_and_skips_damage() {
        let mut w = ScnWriter::new();
        w.progress(1 << 20);
        w.progress(2 << 20);
        w.progress(3 << 20);
        let mut bytes = w.finish();
        let c = Container::parse(&bytes).unwrap();
        assert_eq!(c.version, 1);
        assert_eq!(c.groups.iter().map(|g| g.name()).collect::<Vec<_>>(), ["OOGR", "OOGR", "OOGR"]);
        assert!(c.damage.is_empty());
        // Corrupt the second group's payload: its CRC fails, the walk resumes at the third.
        let second = c.groups[1].offset;
        bytes[second + 20] ^= 0xFF;
        let c = Container::parse(&bytes).unwrap();
        assert_eq!(c.groups.len(), 2);
        assert_eq!(c.damage.len(), 1);
        assert!(Container::parse(&bytes[..0x90]).is_none());
        assert!(Container::parse(b"not a scan file").is_none());
    }
}
