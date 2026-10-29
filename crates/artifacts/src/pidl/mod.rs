//! Shell item (PIDL) decoding: item-id lists from OpenSavePidlMRU, LNK target lists and
//! shellbags turned into typed items and readable paths.

mod item;
mod known;

pub(crate) use item::{ItemKind, ShellItem};
use strata_kernel::bytes::u16_le;

const MAX_ITEMS: usize = 64;

/// Items of an item-id list, in order. Unreadable items are skipped; a broken size ends it.
pub(crate) fn items(data: &[u8]) -> Vec<ShellItem> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while out.len() < MAX_ITEMS {
        let Some(size) = u16_le(data, off).map(usize::from) else { break };
        if size < 3 {
            break;
        }
        let Some(raw) = data.get(off..off + size) else { break };
        out.extend(ShellItem::parse(raw));
        off += size;
    }
    out
}

/// Decode an item-id list into a `\`-joined path (best effort, never fails).
pub(crate) fn decode(data: &[u8]) -> String {
    join(&items(data))
}

/// `\`-joined names. A "My Computer" root in front of a drive is dropped (`C:\Users`).
pub(crate) fn join(items: &[ShellItem]) -> String {
    let computer = items.first().is_some_and(|i| i.kind == ItemKind::Root && i.name == "My Computer");
    let skip = usize::from(computer && items.get(1).is_some_and(|i| i.kind == ItemKind::Volume));
    items[skip..].iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join("\\")
}

/// Mark items below a portable-device root (MTP phones, cameras) as device items.
pub(crate) fn mark_devices(items: &mut [ShellItem]) {
    if let Some(root) = items.iter().position(|i| i.kind == ItemKind::Root && known::is_device_root(&i.name)) {
        for i in &mut items[root + 1..] {
            i.kind = ItemKind::Device;
        }
    }
}

/// A file-entry shell item (`0x31` folder / `0x32` file) with a version-9 extension block
/// carrying the long name and created/accessed DOS times. `dos` = (date, time) for all three.
#[cfg(test)]
pub(crate) fn file_item_at(short: &str, long: &str, folder: bool, dos: (u16, u16)) -> Vec<u8> {
    let mut item = vec![0u8, 0, if folder { 0x31 } else { 0x32 }, 0];
    item.extend_from_slice(&[0; 4]);
    item.extend_from_slice(&dos.0.to_le_bytes());
    item.extend_from_slice(&dos.1.to_le_bytes());
    item.extend_from_slice(&[0x10, 0]);
    item.extend_from_slice(short.as_bytes());
    item.push(0);
    if item.len() % 2 == 1 {
        item.push(0);
    }
    let mut ext = vec![0u8; 0x2E];
    ext[2..4].copy_from_slice(&9u16.to_le_bytes());
    ext[4..8].copy_from_slice(&0xBEEF_0004u32.to_le_bytes());
    for at in [8, 12] {
        ext[at..at + 2].copy_from_slice(&dos.0.to_le_bytes());
        ext[at + 2..at + 4].copy_from_slice(&dos.1.to_le_bytes());
    }
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
pub(crate) fn file_item(short: &str, long: &str) -> Vec<u8> {
    file_item_at(short, long, false, (0, 0))
}

/// Volume item for `letter` (`C`).
#[cfg(test)]
pub(crate) fn volume_item(letter: char) -> Vec<u8> {
    let mut item = vec![0x19, 0, 0x2F];
    item.extend_from_slice(format!("{letter}:\\").as_bytes());
    item.resize(0x19, 0);
    item
}

/// Root folder item for "My Computer".
#[cfg(test)]
pub(crate) fn my_computer_item() -> Vec<u8> {
    let mut root = vec![0x14, 0, 0x1F, 0x50];
    root.extend_from_slice(&[0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D]);
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_volume_and_file() {
        let mut pidl = my_computer_item();
        pidl.extend(volume_item('C'));
        pidl.extend(file_item("WALLET~1.DAT", "wallet.dat"));
        pidl.extend_from_slice(&[0, 0]);
        assert_eq!(decode(&pidl), "C:\\wallet.dat");
        assert_eq!(decode(&[0xff, 0xff, 0x31]), "");
        assert_eq!(decode(&[]), "");
    }

    #[test]
    fn garbage_item_lists_never_panic() {
        let mut s = 0x2545_F491_4F6C_DD1Du64;
        for round in 0..2000usize {
            let mut data: Vec<u8> = (0..round % 300)
                .map(|_| {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    s as u8
                })
                .collect();
            if data.len() > 3 {
                let len = data.len() as u16;
                data[..2].copy_from_slice(&len.to_le_bytes());
                data[2] = [0x1F, 0x2F, 0x31, 0x35, 0x41, 0x61, 0x74, 0x00][round % 8];
            }
            let _ = decode(&data);
        }
    }

    #[test]
    fn file_entries_carry_times_and_long_names() {
        let date = ((2011 - 1980) << 9) | (5 << 5) | 14;
        let time = (17 << 11) | (36 << 5) | 4;
        let item = ShellItem::parse(&file_item_at("BITCOI~1", "Bitcoin wallets", true, (date, time))).unwrap();
        assert_eq!((item.kind, item.name.as_str()), (ItemKind::Folder, "Bitcoin wallets"));
        assert_eq!(item.modified.unwrap().to_string(), "2011-05-14 17:36:08");
        assert_eq!(item.created, item.modified);
        assert_eq!(item.accessed, item.modified);
    }
}
