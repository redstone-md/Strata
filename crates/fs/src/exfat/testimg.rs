//! Byte builder for tiny synthetic exFAT volumes (512-byte sectors and clusters).

use super::boot::boot_checksum;
use super::entry::set_checksum;
use std::collections::HashMap;

pub(super) const CS: usize = 512;
const FAT_OFFSET: usize = 24;
const FAT_SECTORS: usize = 8;
const HEAP_OFFSET: usize = 32;
pub(super) const CLUSTERS: usize = 256;
pub(super) const ROOT: u32 = 4;
/// 2019-03-07 14:20:30 as an exFAT (DOS) timestamp.
pub(super) const STAMP: u32 = ((((2019 - 1980) << 9) | (3 << 5) | 7) << 16) | ((14 << 11) | (20 << 5) | 15);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Dir {
    Root,
    Cluster(u32),
}

pub(super) struct ExfatImage {
    bytes: Vec<u8>,
    bitmap: Vec<u8>,
    next_slot: HashMap<Dir, usize>,
}

impl ExfatImage {
    pub(super) fn new() -> Self {
        let mut bytes = vec![0u8; (HEAP_OFFSET + CLUSTERS) * 512];
        let s = &mut bytes[..512];
        s[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        s[3..11].copy_from_slice(b"EXFAT   ");
        s[72..80].copy_from_slice(&((HEAP_OFFSET + CLUSTERS) as u64).to_le_bytes());
        s[80..84].copy_from_slice(&(FAT_OFFSET as u32).to_le_bytes());
        s[84..88].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
        s[88..92].copy_from_slice(&(HEAP_OFFSET as u32).to_le_bytes());
        s[92..96].copy_from_slice(&(CLUSTERS as u32).to_le_bytes());
        s[96..100].copy_from_slice(&ROOT.to_le_bytes());
        s[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
        s[108] = 9;
        s[109] = 0;
        s[110] = 1;
        s[510] = 0x55;
        s[511] = 0xAA;
        let mut img = Self { bytes, bitmap: vec![0; CLUSTERS / 8], next_slot: HashMap::new() };
        img.set_fat(0, 0xFFFF_FFF8);
        img.set_fat(1, 0xFFFF_FFFF);
        // Bitmap (2), up-case table (3), root directory (4, 5).
        img.chain(&[2]);
        img.chain(&[3]);
        img.chain(&[ROOT, ROOT + 1]);
        let mut label = [0u8; 32];
        label[0] = 0x83;
        label[1] = 5;
        for (i, u) in "WALLY".encode_utf16().enumerate() {
            label[2 + 2 * i..4 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        let mut bitmap = [0u8; 32];
        bitmap[0] = 0x81;
        bitmap[20..24].copy_from_slice(&2u32.to_le_bytes());
        bitmap[24..32].copy_from_slice(&((CLUSTERS / 8) as u64).to_le_bytes());
        let mut upcase = [0u8; 32];
        upcase[0] = 0x82;
        upcase[20..24].copy_from_slice(&3u32.to_le_bytes());
        upcase[24..32].copy_from_slice(&128u64.to_le_bytes());
        img.add(Dir::Root, &[label, bitmap, upcase]);
        img
    }

    pub(super) fn set_fat(&mut self, cluster: u32, value: u32) {
        let off = FAT_OFFSET * 512 + cluster as usize * 4;
        self.bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Mark clusters allocated in the bitmap only (`NoFatChain` files).
    pub(super) fn allocate(&mut self, clusters: &[u32]) {
        for c in clusters {
            let i = *c as usize - 2;
            self.bitmap[i / 8] |= 1 << (i % 8);
        }
    }

    /// Allocate and link clusters in order, ending with end-of-chain.
    pub(super) fn chain(&mut self, clusters: &[u32]) {
        self.allocate(clusters);
        for w in clusters.windows(2) {
            self.set_fat(w[0], w[1]);
        }
        if let Some(last) = clusters.last() {
            self.set_fat(*last, 0xFFFF_FFFF);
        }
    }

    pub(super) fn cluster_offset(cluster: u32) -> usize {
        HEAP_OFFSET * 512 + (cluster as usize - 2) * CS
    }

    pub(super) fn write_clusters(&mut self, clusters: &[u32], data: &[u8]) {
        for (c, part) in clusters.iter().zip(data.chunks(CS)) {
            let off = Self::cluster_offset(*c);
            self.bytes[off..off + part.len()].copy_from_slice(part);
        }
    }

    pub(super) fn add(&mut self, dir: Dir, entries: &[[u8; 32]]) {
        let slot = self.next_slot.entry(dir).or_insert(0);
        let base = Self::cluster_offset(match dir {
            Dir::Root => ROOT,
            Dir::Cluster(c) => c,
        });
        for e in entries {
            let off = base + *slot * 32;
            self.bytes[off..off + 32].copy_from_slice(e);
            *slot += 1;
        }
    }

    /// Write the bitmap and the boot region checksum, and copy the main region to the backup.
    pub(super) fn finish(mut self) -> Vec<u8> {
        let at = Self::cluster_offset(2);
        self.bytes[at..at + self.bitmap.len()].copy_from_slice(&self.bitmap);
        let sum = boot_checksum(&self.bytes[..11 * 512]);
        for i in 0..128 {
            let off = 11 * 512 + i * 4;
            self.bytes[off..off + 4].copy_from_slice(&sum.to_le_bytes());
        }
        let main = self.bytes[..12 * 512].to_vec();
        self.bytes[12 * 512..24 * 512].copy_from_slice(&main);
        self.bytes
    }
}

/// File entry set (File, Stream Extension, File Names) with a valid checksum.
pub(super) fn file_set(name: &str, attr: u16, first: u32, size: u64, no_fat_chain: bool) -> Vec<[u8; 32]> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let name_entries = units.len().div_ceil(15).max(1);
    let mut set = vec![[0u8; 32]; 2 + name_entries];
    set[0][0] = 0x85;
    set[0][1] = (1 + name_entries) as u8;
    set[0][4..6].copy_from_slice(&attr.to_le_bytes());
    for at in [8, 12, 16] {
        set[0][at..at + 4].copy_from_slice(&STAMP.to_le_bytes());
    }
    set[0][21] = 50;
    set[0][23] = 0x80 | 8;
    set[1][0] = 0xC0;
    set[1][1] = 0x01 | if no_fat_chain { 0x02 } else { 0 };
    set[1][3] = units.len() as u8;
    set[1][8..16].copy_from_slice(&size.to_le_bytes());
    set[1][20..24].copy_from_slice(&first.to_le_bytes());
    set[1][24..32].copy_from_slice(&size.to_le_bytes());
    for (k, chunk) in units.chunks(15).enumerate() {
        let e = &mut set[2 + k];
        e[0] = 0xC1;
        for (j, u) in chunk.iter().enumerate() {
            e[2 + 2 * j..4 + 2 * j].copy_from_slice(&u.to_le_bytes());
        }
    }
    let flat: Vec<u8> = set.iter().flatten().copied().collect();
    let sum = set_checksum(&flat, false);
    set[0][2..4].copy_from_slice(&sum.to_le_bytes());
    set
}

/// Clear the in-use bit of every entry, as deletion does.
pub(super) fn deleted(mut set: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    for e in &mut set {
        e[0] &= 0x7F;
    }
    set
}
