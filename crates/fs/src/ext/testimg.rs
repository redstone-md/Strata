//! Byte builders for tiny synthetic ext2/ext4 volumes: 1 KiB blocks, 32 inodes of 256 bytes per
//! group, one or two groups (the second carries the backup superblock and descriptors).

pub(super) const BS: usize = 1024;
const IPG: usize = 32;
const ISZ: usize = 256;
const BPG: usize = 8192;
const ITABLE_BLOCKS: usize = IPG * ISZ / BS;
/// 2020-01-01 00:00:00 UTC.
pub(super) const T: u32 = 1_577_836_800;

pub(super) const S_IFDIR: u16 = 0x41ED;
pub(super) const S_IFREG: u16 = 0x81A4;
pub(super) const S_IFLNK: u16 = 0xA1FF;
pub(super) const EXTENTS_FL: u32 = 0x8_0000;
pub(super) const INLINE_FL: u32 = 0x1000_0000;

pub(super) struct ExtImage {
    bytes: Vec<u8>,
    groups: usize,
    next_block: usize,
}

/// Group `g` layout: [backup sb + gdt in group 1], block bitmap, inode bitmap, inode table.
fn group_meta(g: usize) -> (usize, usize, usize) {
    let base = 1 + g * BPG + 2;
    (base, base + 1, base + 2)
}

impl ExtImage {
    pub(super) fn new(groups: usize, ext4: bool) -> Self {
        let blocks = if groups == 1 { 1024 } else { 1 + BPG + 256 };
        let mut img = Self { bytes: vec![0u8; blocks * BS], groups, next_block: group_meta(0).2 + ITABLE_BLOCKS };
        let sb = img.superblock(blocks, ext4, 0);
        img.bytes[1024..2048].copy_from_slice(&sb);
        img.write_gdt(2);
        if groups > 1 {
            let at = (1 + BPG) * BS;
            let backup = img.superblock(blocks, ext4, 1);
            img.bytes[at..at + 1024].copy_from_slice(&backup);
            img.write_gdt(2 + BPG);
        }
        for g in 0..groups {
            let (_, _, table) = group_meta(g);
            let first = 1 + g * BPG;
            for b in first..table + ITABLE_BLOCKS {
                img.mark_block(b);
            }
        }
        for ino in 1..=10 {
            img.mark_inode(ino);
        }
        img
    }

    fn superblock(&self, blocks: usize, ext4: bool, group: u16) -> Vec<u8> {
        let mut sb = vec![0u8; 1024];
        let put = |sb: &mut Vec<u8>, off: usize, v: &[u8]| sb[off..off + v.len()].copy_from_slice(v);
        put(&mut sb, 0x00, &((IPG * self.groups) as u32).to_le_bytes());
        put(&mut sb, 0x04, &(blocks as u32).to_le_bytes());
        put(&mut sb, 0x14, &1u32.to_le_bytes());
        put(&mut sb, 0x18, &0u32.to_le_bytes());
        put(&mut sb, 0x20, &(BPG as u32).to_le_bytes());
        put(&mut sb, 0x28, &(IPG as u32).to_le_bytes());
        put(&mut sb, 0x38, &0xEF53u16.to_le_bytes());
        put(&mut sb, 0x4C, &1u32.to_le_bytes());
        put(&mut sb, 0x54, &11u32.to_le_bytes());
        put(&mut sb, 0x58, &(ISZ as u16).to_le_bytes());
        put(&mut sb, 0x5A, &group.to_le_bytes());
        let (compat, incompat) = if ext4 { (0x4u32, 0x2 | 0x40 | 0x8000u32) } else { (0, 0x2) };
        put(&mut sb, 0x5C, &compat.to_le_bytes());
        put(&mut sb, 0x60, &incompat.to_le_bytes());
        put(&mut sb, 0x64, &0x3u32.to_le_bytes());
        put(&mut sb, 0xE0, &if ext4 { 8u32 } else { 0 }.to_le_bytes());
        sb
    }

    fn write_gdt(&mut self, block: usize) {
        for g in 0..self.groups {
            let (bb, ib, it) = group_meta(g);
            let at = block * BS + g * 32;
            self.bytes[at..at + 4].copy_from_slice(&(bb as u32).to_le_bytes());
            self.bytes[at + 4..at + 8].copy_from_slice(&(ib as u32).to_le_bytes());
            self.bytes[at + 8..at + 12].copy_from_slice(&(it as u32).to_le_bytes());
        }
    }

    fn mark_block(&mut self, block: usize) {
        let i = block - 1;
        let (bb, _, _) = group_meta(i / BPG);
        self.bytes[bb * BS + (i % BPG) / 8] |= 1 << (i % 8);
    }

    fn mark_inode(&mut self, ino: usize) {
        let i = ino - 1;
        let (_, ib, _) = group_meta(i / IPG);
        self.bytes[ib * BS + (i % IPG) / 8] |= 1 << (i % 8);
    }

    /// Allocate `n` consecutive data blocks in group 0 (marked used unless `free`).
    pub(super) fn alloc(&mut self, n: usize, free: bool) -> usize {
        let b = self.next_block;
        self.next_block += n;
        if !free {
            (b..b + n).for_each(|x| self.mark_block(x));
        }
        b
    }

    pub(super) fn write(&mut self, block: usize, data: &[u8]) {
        self.bytes[block * BS..block * BS + data.len()].copy_from_slice(data);
    }

    pub(super) fn inode_offset(ino: usize) -> usize {
        let i = ino - 1;
        group_meta(i / IPG).2 * BS + (i % IPG) * ISZ
    }

    pub(super) fn set_inode(&mut self, ino: usize, raw: &[u8], in_use: bool) {
        let at = Self::inode_offset(ino);
        self.bytes[at..at + ISZ].copy_from_slice(raw);
        if in_use {
            self.mark_inode(ino);
        }
    }

    pub(super) fn corrupt_primary_superblock(&mut self) {
        self.bytes[1024 + 0x38] = 0;
    }

    /// Journal inode 8 over `len` blocks holding one descriptor that logs the inode-table block
    /// containing `ino`, with `old` in place of the inode's current bytes.
    pub(super) fn add_journal(&mut self, ino: usize, old: &[u8]) {
        let len = 8;
        let start = self.alloc(len, false);
        self.set_inode(8, &inode(S_IFREG, (len * BS) as u64, 1, EXTENTS_FL, extents(&[(0, len as u16, start as u32)])), true);
        let be = |v: u32| v.to_be_bytes();
        let mut jsb = vec![0u8; BS];
        jsb[0..4].copy_from_slice(&be(0xC03B_3998));
        jsb[4..8].copy_from_slice(&be(4));
        jsb[0x0C..0x10].copy_from_slice(&be(BS as u32));
        jsb[0x10..0x14].copy_from_slice(&be(len as u32));
        jsb[0x14..0x18].copy_from_slice(&be(1));
        self.write(start, &jsb);
        let at = Self::inode_offset(ino);
        let fs_block = at / BS;
        let mut desc = vec![0u8; BS];
        desc[0..4].copy_from_slice(&be(0xC03B_3998));
        desc[4..8].copy_from_slice(&be(1));
        desc[8..12].copy_from_slice(&be(7));
        desc[12..16].copy_from_slice(&be(fs_block as u32));
        desc[18..20].copy_from_slice(&0x0008u16.to_be_bytes());
        self.write(start + 1, &desc);
        let mut copy = self.bytes[fs_block * BS..(fs_block + 1) * BS].to_vec();
        let within = at % BS;
        copy[within..within + ISZ].copy_from_slice(old);
        self.write(start + 2, &copy);
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A 256-byte inode with all four times at [`T`] (+0.5 s crtime) and the given `i_block`.
pub(super) fn inode(mode: u16, size: u64, links: u16, flags: u32, iblock: [u8; 60]) -> Vec<u8> {
    let mut r = vec![0u8; ISZ];
    r[0..2].copy_from_slice(&mode.to_le_bytes());
    r[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    r[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    for off in [0x08, 0x0C, 0x10, 0x90] {
        r[off..off + 4].copy_from_slice(&T.to_le_bytes());
    }
    r[0x94..0x98].copy_from_slice(&(500_000_000u32 << 2).to_le_bytes());
    r[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    r[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    r[0x28..0x64].copy_from_slice(&iblock);
    r[0x64..0x68].copy_from_slice(&7u32.to_le_bytes());
    r[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
    r
}

/// Mark an inode deleted the ext3/4 way (links 0, dtime) and optionally wipe its pointers.
pub(super) fn deleted(mut raw: Vec<u8>, wipe: bool) -> Vec<u8> {
    raw[0x1A..0x1C].fill(0);
    raw[0x14..0x18].copy_from_slice(&(T + 60).to_le_bytes());
    if wipe {
        raw[4..8].fill(0);
        let mut empty = [0u8; 60];
        if u16::from_le_bytes([raw[0x28], raw[0x29]]) == 0xF30A {
            empty[..12].copy_from_slice(&raw[0x28..0x34]);
            empty[2..4].fill(0);
        }
        raw[0x28..0x64].copy_from_slice(&empty);
    }
    raw
}

/// Extent root in `i_block`: leaf entries `(logical, len, start)`.
pub(super) fn extents(list: &[(u32, u16, u32)]) -> [u8; 60] {
    extent_node(list, 0, 4)
}

/// An extent node (header + entries); depth > 0 makes entries index entries `(logical, _, child)`.
pub(super) fn extent_node<const N: usize>(list: &[(u32, u16, u32)], depth: u16, max: u16) -> [u8; N] {
    let mut b = [0u8; N];
    b[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    b[2..4].copy_from_slice(&(list.len() as u16).to_le_bytes());
    b[4..6].copy_from_slice(&max.to_le_bytes());
    b[6..8].copy_from_slice(&depth.to_le_bytes());
    for (i, (lblk, len, start)) in list.iter().enumerate() {
        let e = 12 + i * 12;
        b[e..e + 4].copy_from_slice(&lblk.to_le_bytes());
        if depth == 0 {
            b[e + 4..e + 6].copy_from_slice(&len.to_le_bytes());
            b[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
        } else {
            b[e + 4..e + 8].copy_from_slice(&start.to_le_bytes());
        }
    }
    b
}

/// Classic block map: up to 15 pointers.
pub(super) fn block_ptrs(ptrs: &[u32]) -> [u8; 60] {
    let mut b = [0u8; 60];
    for (i, p) in ptrs.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&p.to_le_bytes());
    }
    b
}

/// One directory block. Entries flagged deleted are hidden in the previous entry's `rec_len`.
pub(super) fn dir_block(entries: &[(u32, &str, u8, bool)]) -> Vec<u8> {
    let mut out = vec![0u8; BS];
    let mut pos = 0;
    let mut live_at = None;
    for (ino, name, ftype, gone) in entries {
        let real = (8 + name.len()).next_multiple_of(4);
        out[pos..pos + 4].copy_from_slice(&ino.to_le_bytes());
        out[pos + 4..pos + 6].copy_from_slice(&(real as u16).to_le_bytes());
        out[pos + 6] = name.len() as u8;
        out[pos + 7] = *ftype;
        out[pos + 8..pos + 8 + name.len()].copy_from_slice(name.as_bytes());
        match (gone, live_at) {
            (true, Some(prev)) => grow(&mut out, prev, real),
            _ => live_at = Some(pos),
        }
        pos += real;
    }
    if let Some(prev) = live_at {
        grow(&mut out, prev, BS - pos);
    }
    out
}

fn grow(block: &mut [u8], at: usize, by: usize) {
    let cur = u16::from_le_bytes([block[at + 4], block[at + 5]]);
    block[at + 4..at + 6].copy_from_slice(&(cur + by as u16).to_le_bytes());
}

/// Inline data: first 60 bytes in `i_block`, the rest in the in-inode `system.data` xattr.
pub(super) fn inline_inode(mode: u16, data: &[u8]) -> Vec<u8> {
    let mut head = [0u8; 60];
    let n = data.len().min(60);
    head[..n].copy_from_slice(&data[..n]);
    let mut raw = inode(mode, data.len() as u64, 1, INLINE_FL, head);
    let tail = &data[n..];
    let start = 128 + 32;
    raw[start..start + 4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
    let e = start + 4;
    raw[e] = 4;
    raw[e + 1] = 7;
    let value_off = 32u16;
    raw[e + 2..e + 4].copy_from_slice(&value_off.to_le_bytes());
    raw[e + 8..e + 12].copy_from_slice(&(tail.len() as u32).to_le_bytes());
    raw[e + 16..e + 20].copy_from_slice(b"data");
    let v = e + value_off as usize;
    raw[v..v + tail.len()].copy_from_slice(tail);
    raw
}
