//! Minimal shell-item (PIDL) decoding: enough to turn an OpenSavePidlMRU / LastVisitedPidlMRU
//! entry into a readable path.

use crate::text::ansi_at;
use strata_kernel::bytes::{u16_le, u32_le, u8_at};

const EXT_FILE_ENTRY: u32 = 0xBEEF_0004;

/// Decode an item-id list into `\`-joined names (best effort, never fails).
pub(crate) fn decode(data: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut off = 0usize;
    while parts.len() < 64 {
        let Some(size) = u16_le(data, off).map(usize::from) else { break };
        if size < 3 {
            break;
        }
        let Some(item) = data.get(off..off + size) else { break };
        if let Some(name) = item_name(item) {
            parts.push(name);
        }
        off += size;
    }
    parts.join("\\")
}

fn item_name(item: &[u8]) -> Option<String> {
    let class = u8_at(item, 2)?;
    match class & 0x70 {
        // Root folder (My Computer etc.).
        0x10 => Some(known_root(item)),
        // Volume: "C:\".
        0x20 => Some(ansi_at(item, 3, 20).trim_end_matches('\\').to_string()).filter(|s| !s.is_empty()),
        // File entry: short name, then the long name from the 0xBEEF0004 extension block.
        0x30 => {
            let short = ansi_at(item, 14, item.len().saturating_sub(14));
            Some(long_name(item).unwrap_or(short)).filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

fn known_root(item: &[u8]) -> String {
    match item.get(4..20) {
        Some([0xE0, 0x4F, 0xD0, 0x20, ..]) => "My Computer".into(),
        Some([0x80, 0x53, 0x1C, 0x87, ..]) => "Users".into(),
        _ => "Desktop".into(),
    }
}

/// Long name from the file-entry extension block (version-dependent offset; candidates are
/// tried in order and the first plausible name wins).
fn long_name(item: &[u8]) -> Option<String> {
    let ext_off = (4..item.len().saturating_sub(8)).find(|&o| u32_le(item, o + 4) == Some(EXT_FILE_ENTRY))?;
    let version = u16_le(item, ext_off + 2)?;
    let candidates: &[usize] = match version {
        0..=6 => &[0x12, 0x14],
        7 => &[0x1A, 0x1C],
        8 => &[0x1E, 0x1A],
        _ => &[0x2E, 0x22, 0x1E],
    };
    candidates.iter().find_map(|&c| {
        let s = crate::text::utf16_at(item, ext_off + c, item.len());
        (s.chars().count() >= 1 && s.chars().all(|ch| !ch.is_control())).then_some(s)
    })
}

#[cfg(test)]
pub(crate) fn file_item(short: &str, long: &str) -> Vec<u8> {
    let mut item = vec![0u8, 0, 0x32, 0];
    item.extend_from_slice(&[0; 10]);
    item.extend_from_slice(short.as_bytes());
    item.push(0);
    if item.len() % 2 == 1 {
        item.push(0);
    }
    let mut ext = vec![0u8; 0x2E];
    ext[2..4].copy_from_slice(&9u16.to_le_bytes());
    ext[4..8].copy_from_slice(&EXT_FILE_ENTRY.to_le_bytes());
    ext.extend(long.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    ext.extend_from_slice(&[0, 0]);
    let ext_len = ext.len() as u16;
    ext[0..2].copy_from_slice(&ext_len.to_le_bytes());
    item.extend_from_slice(&ext);
    let len = item.len() as u16;
    item[0..2].copy_from_slice(&len.to_le_bytes());
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_volume_and_file() {
        let mut pidl = vec![0x19, 0, 0x2F];
        pidl.extend_from_slice(b"C:\\");
        pidl.resize(0x19, 0);
        pidl.extend(file_item("WALLET~1.DAT", "wallet.dat"));
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(decode(&pidl), "C:\\wallet.dat");
        assert_eq!(decode(&[0xff, 0xff, 0x31]), "");
        assert_eq!(decode(&[]), "");
    }
}
