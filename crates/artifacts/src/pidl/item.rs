//! One shell item: root folder, volume, file entry (with its `0xBEEF0004` extension block),
//! network location, URI, users-files delegate, and a best-effort fallback for device items.

use super::known;
use crate::text::{ansi_at, guid_at, utf16_at};
use strata_kernel::Timestamp;
use strata_kernel::bytes::{u8_at, u16_le, u32_le};

const EXT_FILE_ENTRY: u32 = 0xBEEF_0004;
const DELEGATE_SIG: &[u8; 4] = b"CFSF";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ItemKind {
    Root,
    Volume,
    Folder,
    File,
    Network,
    Uri,
    /// Portable device (MTP phone, camera, USB player) or an item below one.
    Device,
    #[default]
    Unknown,
}

/// A decoded shell item. Times are FAT-precision local clock values from the item itself.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ShellItem {
    pub(crate) kind: ItemKind,
    pub(crate) name: String,
    pub(crate) modified: Option<Timestamp>,
    pub(crate) created: Option<Timestamp>,
    pub(crate) accessed: Option<Timestamp>,
}

impl ShellItem {
    fn named(kind: ItemKind, name: String) -> Option<Self> {
        (!name.trim().is_empty()).then(|| Self { kind, name, ..Self::default() })
    }

    /// Parse an item (`item` includes its 2-byte size). `None` when nothing readable is in it.
    pub(crate) fn parse(item: &[u8]) -> Option<Self> {
        let class = u8_at(item, 2)?;
        match class {
            0x1F => Self::named(ItemKind::Root, known::root_name(&guid_at(item, 4)?)),
            0x20..=0x2F => Self::named(ItemKind::Volume, ansi_at(item, 3, 20).trim_end_matches('\\').to_string()),
            0x30..=0x3F => file_entry(item, 0, class),
            0x40..=0x4F | 0xC3 => network(item),
            0x61 => uri(item),
            0x74 if item.get(6..10) == Some(DELEGATE_SIG) => {
                let inner = u8_at(item, 12)?;
                file_entry(item, 10, inner)
            }
            _ => Self::named(ItemKind::Unknown, longest_utf16(item)),
        }
    }
}

/// File entry at `item[base..]`: size u32 at +4, modified DOS date/time at +8, primary name at
/// +14 (UTF-16 when class bit 0x04 is set); long name and created/accessed times in the
/// extension block.
fn file_entry(item: &[u8], base: usize, class: u8) -> Option<ShellItem> {
    let unicode = class & 0x04 != 0;
    let short =
        if unicode { utf16_at(item, base + 14, item.len()) } else { ansi_at(item, base + 14, item.len().saturating_sub(base + 14)) };
    let dos = |at: usize| Timestamp::from_dos(u16_le(item, at)?, u16_le(item, at + 2)?);
    let ext = extension(item);
    let mut out = ShellItem {
        kind: if class & 0x01 != 0 { ItemKind::Folder } else { ItemKind::File },
        name: ext.and_then(|e| long_name(item, e)).unwrap_or(short),
        modified: dos(base + 8),
        ..ShellItem::default()
    };
    if let Some(e) = ext {
        out.created = dos(e + 8);
        out.accessed = dos(e + 12);
    }
    (!out.name.is_empty()).then_some(out)
}

/// Offset of the `0xBEEF0004` extension block (its size field).
fn extension(item: &[u8]) -> Option<usize> {
    (4..item.len().saturating_sub(8)).find(|&o| u32_le(item, o + 4) == Some(EXT_FILE_ENTRY))
}

/// Long name from the extension block (version-dependent offset; candidates are tried in order
/// and the first plausible name wins).
fn long_name(item: &[u8], ext: usize) -> Option<String> {
    let version = u16_le(item, ext + 2)?;
    let candidates: &[usize] = match version {
        0..=6 => &[0x12, 0x14],
        7 => &[0x1A, 0x1C],
        8 => &[0x1E, 0x1A],
        _ => &[0x2E, 0x22, 0x1E],
    };
    candidates.iter().find_map(|&c| {
        let s = utf16_at(item, ext + c, item.len());
        (!s.is_empty() && s.chars().all(|ch| !ch.is_control())).then_some(s)
    })
}

/// Network location (`\\server\share`), stored as ANSI after a flags byte.
fn network(item: &[u8]) -> Option<ShellItem> {
    let start = if u8_at(item, 4).is_some_and(|b| b >= 0x20) { 4 } else { 5 };
    ShellItem::named(ItemKind::Network, ansi_at(item, start, item.len()))
}

/// URI item: the URL is found by its scheme separator (ANSI or UTF-16).
fn uri(item: &[u8]) -> Option<ShellItem> {
    let ascii = item.windows(3).position(|w| w == b"://").map(|p| {
        let start = (0..p).rev().take_while(|&i| item[i].is_ascii_alphanumeric()).last().unwrap_or(p);
        ansi_at(item, start, item.len())
    });
    let wide = || {
        let needle = [b':', 0, b'/', 0, b'/', 0];
        let p = item.windows(6).position(|w| w == needle)?;
        let mut start = p;
        while start >= 2 && item[start - 2].is_ascii_alphanumeric() && item[start - 1] == 0 {
            start -= 2;
        }
        Some(utf16_at(item, start, item.len()))
    };
    ShellItem::named(ItemKind::Uri, ascii.or_else(wide).unwrap_or_default())
}

/// Longest run of readable UTF-16 (letters, digits, ASCII punctuation; at least three
/// characters): names of device items.
fn longest_utf16(item: &[u8]) -> String {
    let readable = |u: &u16| char::from_u32(u32::from(*u)).is_some_and(|c| (' '..='~').contains(&c) || c.is_alphanumeric());
    let mut best = String::new();
    for parity in 0..2 {
        let units: Vec<u16> = item.get(parity..).unwrap_or(&[]).as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        for run in units.split(|u| !readable(u)) {
            if run.len() >= 3 && run.len() > best.chars().count() {
                best = String::from_utf16_lossy(run);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_volumes_and_fallbacks() {
        let mut root = vec![0x14, 0, 0x1F, 0x50];
        root.extend_from_slice(&[0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D]);
        assert_eq!(ShellItem::parse(&root).unwrap().name, "My Computer");
        let mut uri = vec![0, 0, 0x61, 0x80, 0, 0];
        uri.extend("https://bitcointalk.org/".encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        assert_eq!(ShellItem::parse(&uri).unwrap().name, "https://bitcointalk.org/");
        let mut net = vec![0, 0, 0x41, 0x82, 0x00];
        net.extend_from_slice(b"\\\\SERVER\\share\0");
        assert_eq!(ShellItem::parse(&net).unwrap().name, "\\\\SERVER\\share");
        let mut dev = vec![0, 0, 0x00, 0x00, 0x11, 0x22];
        dev.extend("Apple iPhone".encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        assert_eq!(ShellItem::parse(&dev).unwrap().name, "Apple iPhone");
        assert!(ShellItem::parse(&[0, 0]).is_none());
        assert!(ShellItem::parse(&[0, 0, 0x31]).is_none());
    }
}
