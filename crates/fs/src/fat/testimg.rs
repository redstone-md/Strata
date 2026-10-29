//! Byte builders for tiny synthetic FAT12/16/32 volumes (512-byte clusters).

use std::collections::HashMap;

pub(super) const CS: usize = 512;
/// 2012-01-15 10:30:20 as DOS date/time.
pub(super) const DOS_DATE: u16 = ((2012 - 1980) << 9) | (1 << 5) | 15;
pub(super) const DOS_TIME: u16 = (10 << 11) | (30 << 5) | 10;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Dir {
    Root,
    Cluster(u32),
}

pub(super) struct FatImage {
    bytes: Vec<u8>,
    width: u32,
    reserved: usize,
    fat_sectors: usize,
    root_entries: usize,
    data_start: usize,
    next_slot: HashMap<Dir, usize>,
}

impl FatImage {
    fn build(width: u32, total: usize, reserved: usize, fat_sectors: usize, root_entries: usize) -> Self {
        let mut bytes = vec![0u8; total * 512];
        let s = &mut bytes[..512];
        s[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        s[3..11].copy_from_slice(b"MSDOS5.0");
        s[11..13].copy_from_slice(&512u16.to_le_bytes());
        s[13] = 1;
        s[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        s[16] = 2;
        s[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        s[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        s[21] = 0xF8;
        if width == 32 {
            s[32..36].copy_from_slice(&(total as u32).to_le_bytes());
            s[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
            s[44..48].copy_from_slice(&2u32.to_le_bytes());
            s[19..21].fill(0);
        } else {
            s[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
        }
        s[510] = 0x55;
        s[511] = 0xAA;
        let data_start = (reserved + 2 * fat_sectors) * 512 + root_entries * 32;
        let mut img = Self { bytes, width, reserved, fat_sectors, root_entries, data_start, next_slot: HashMap::new() };
        img.set_fat(0, 0x0FFF_FFF8);
        img.set_fat(1, 0x0FFF_FFFF);
        if width == 32 {
            img.chain(&[2]);
        }
        img
    }

    pub(super) fn fat12() -> Self {
        Self::build(12, 2048, 1, 6, 32)
    }

    pub(super) fn fat16() -> Self {
        Self::build(16, 8192, 1, 32, 64)
    }

    pub(super) fn fat32() -> Self {
        Self::build(32, 8192, 32, 64, 0)
    }

    pub(super) fn set_fat(&mut self, cluster: u32, value: u32) {
        for copy in 0..2 {
            self.set_fat_copy(copy, cluster, value);
        }
    }

    pub(super) fn set_fat_copy(&mut self, copy: usize, cluster: u32, value: u32) {
        let base = (self.reserved + copy * self.fat_sectors) * 512;
        let c = cluster as usize;
        match self.width {
            12 => {
                let off = base + c * 3 / 2;
                let v = (value & 0xFFF) as u16;
                let cur = u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]);
                let new = if c.is_multiple_of(2) { (cur & 0xF000) | v } else { (cur & 0x000F) | (v << 4) };
                self.bytes[off..off + 2].copy_from_slice(&new.to_le_bytes());
            }
            16 => self.bytes[base + c * 2..base + c * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes()),
            _ => self.bytes[base + c * 4..base + c * 4 + 4].copy_from_slice(&(value & 0x0FFF_FFFF).to_le_bytes()),
        }
    }

    /// Link clusters in order and terminate with end-of-chain.
    pub(super) fn chain(&mut self, clusters: &[u32]) {
        for w in clusters.windows(2) {
            self.set_fat(w[0], w[1]);
        }
        if let Some(last) = clusters.last() {
            self.set_fat(*last, 0x0FFF_FFFF);
        }
    }

    pub(super) fn cluster_offset(&self, cluster: u32) -> usize {
        self.data_start + (cluster as usize - 2) * CS
    }

    /// Write `data` over `clusters` in order (no FAT change).
    pub(super) fn write_clusters(&mut self, clusters: &[u32], data: &[u8]) {
        for (c, part) in clusters.iter().zip(data.chunks(CS)) {
            let off = self.cluster_offset(*c);
            self.bytes[off..off + part.len()].copy_from_slice(part);
        }
    }

    pub(super) fn add(&mut self, dir: Dir, slots: &[[u8; 32]]) {
        let slot = self.next_slot.entry(dir).or_insert(0);
        let base = match dir {
            Dir::Root if self.width != 32 => (self.reserved + 2 * self.fat_sectors) * 512,
            Dir::Root => self.data_start,
            Dir::Cluster(c) => self.data_start + (c as usize - 2) * CS,
        };
        for s in slots {
            let off = base + *slot * 32;
            self.bytes[off..off + 32].copy_from_slice(s);
            *slot += 1;
        }
        debug_assert!(dir != Dir::Root || self.width == 32 || *slot <= self.root_entries);
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(super) fn short(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    e[14..16].copy_from_slice(&DOS_TIME.to_le_bytes());
    e[16..18].copy_from_slice(&DOS_DATE.to_le_bytes());
    e[18..20].copy_from_slice(&DOS_DATE.to_le_bytes());
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[22..24].copy_from_slice(&DOS_TIME.to_le_bytes());
    e[24..26].copy_from_slice(&DOS_DATE.to_le_bytes());
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// `.` and `..` entries opening a subdirectory.
pub(super) fn dots(own: u32, parent: u32) -> [[u8; 32]; 2] {
    [short(b".          ", 0x10, own, 0), short(b"..         ", 0x10, parent, 0)]
}

/// LFN slots for `long`, in on-disk order, followed by the 8.3 entry.
pub(super) fn with_lfn(long: &str, entry: [u8; 32]) -> Vec<[u8; 32]> {
    let name: [u8; 11] = entry[..11].try_into().unwrap_or([b' '; 11]);
    let sum = name.iter().fold(0u8, |s, b| s.rotate_right(1).wrapping_add(*b));
    let mut units: Vec<u16> = long.encode_utf16().collect();
    let n = units.len().div_ceil(13);
    if !units.len().is_multiple_of(13) {
        units.push(0);
    }
    units.resize(n * 13, 0xFFFF);
    let mut out = Vec::new();
    for seq in (1..=n).rev() {
        let mut e = [0u8; 32];
        e[0] = seq as u8 | if seq == n { 0x40 } else { 0 };
        e[11] = 0x0F;
        e[13] = sum;
        let part = &units[(seq - 1) * 13..seq * 13];
        let spans = [(1usize, 0usize, 5usize), (14, 5, 6), (28, 11, 2)];
        for (pos, from, count) in spans {
            for j in 0..count {
                e[pos + 2 * j..pos + 2 * j + 2].copy_from_slice(&part[from + j].to_le_bytes());
            }
        }
        out.push(e);
    }
    out.push(entry);
    out
}

/// Mark every slot deleted, as Windows does.
pub(super) fn deleted(mut slots: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    for s in &mut slots {
        s[0] = 0xE5;
    }
    slots
}
