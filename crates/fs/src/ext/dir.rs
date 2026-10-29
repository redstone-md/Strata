//! Directory blocks: live entries along the `rec_len` chain, plus deleted entries recovered
//! from the slack after each entry's real length (ext removes an entry by growing the previous
//! entry's `rec_len` over it). Htree directories are read linearly; their index blocks are
//! recognised and skipped.

use strata_kernel::bytes::{u16_le, u32_le, u8_at};

const HEADER: usize = 8;
const MAX_FILE_TYPE: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirRecord {
    /// 0 when the entry's inode number was cleared on delete.
    pub(super) inode: u32,
    pub(super) name: String,
    pub(super) file_type: u8,
    pub(super) deleted: bool,
    /// Volume offset of the entry.
    pub(super) offset: u64,
}

pub(super) struct DirParser {
    filetype: bool,
    max_inode: u32,
}

impl DirParser {
    pub(super) fn new(filetype: bool, max_inode: u32) -> Self {
        Self { filetype, max_inode }
    }

    /// Parse directory content read from consecutive volume offsets: `blocks` lists each
    /// block's data with its offset. The first block of an htree directory is its dx root.
    pub(super) fn parse(&self, blocks: &[(u64, &[u8])], htree: bool) -> Vec<DirRecord> {
        let mut out = Vec::new();
        for (i, (at, data)) in blocks.iter().enumerate() {
            self.parse_block(data, *at, htree && i == 0, &mut out);
        }
        out
    }

    /// Inline-data directory: 4-byte parent inode, then entries without `.`/`..`.
    pub(super) fn parse_inline(&self, data: &[u8], at: u64) -> Vec<DirRecord> {
        let mut out = Vec::new();
        if let Some(rest) = data.get(4..) {
            self.parse_block(rest, at + 4, false, &mut out);
        }
        out
    }

    fn parse_block(&self, block: &[u8], at: u64, dx_root: bool, out: &mut Vec<DirRecord>) {
        let mut pos = 0usize;
        while pos + HEADER <= block.len() {
            let Some((inode, rec_len, name_len, file_type)) = self.header(block, pos) else { return };
            if rec_len < HEADER || !rec_len.is_multiple_of(4) || pos + rec_len > block.len() {
                // Broken chain: whatever follows is only reachable as slack.
                self.scan_slack(block, pos, block.len(), at, out);
                return;
            }
            let real = (HEADER + name_len).next_multiple_of(4);
            let name = block.get(pos + HEADER..pos + HEADER + name_len).filter(|_| name_len > 0 && HEADER + name_len <= rec_len);
            let is_dot = matches!(name, Some(b".") | Some(b".."));
            if let Some(name) = name.filter(|_| !is_dot) {
                if inode != 0 && inode <= self.max_inode {
                    out.push(record(inode, name, file_type, false, at + pos as u64));
                } else if inode == 0 && valid_name(name) {
                    out.push(record(0, name, file_type, true, at + pos as u64));
                }
            }
            // Index blocks hide dx entries behind a nameless entry (or `..` in the dx root).
            let index_area = (inode == 0 && name_len == 0) || (dx_root && name == Some(b".."));
            if !index_area && real < rec_len {
                self.scan_slack(block, pos + real, pos + rec_len, at, out);
            }
            pos += rec_len;
        }
    }

    fn header(&self, block: &[u8], pos: usize) -> Option<(u32, usize, usize, u8)> {
        let inode = u32_le(block, pos)?;
        let rec_len = usize::from(u16_le(block, pos + 4)?);
        let (name_len, file_type) = if self.filetype {
            (usize::from(u8_at(block, pos + 6)?), u8_at(block, pos + 7)?)
        } else {
            (usize::from(u16_le(block, pos + 6)?), 0)
        };
        Some((inode, rec_len, name_len, file_type))
    }

    /// Stale entries inside `[from, to)`, each checked hard since slack is arbitrary bytes.
    fn scan_slack(&self, block: &[u8], from: usize, to: usize, at: u64, out: &mut Vec<DirRecord>) {
        let mut p = from.next_multiple_of(4);
        while p + HEADER < to {
            match self.stale_at(block, p, to) {
                Some((rec, real)) => {
                    out.push(DirRecord { offset: at + p as u64, ..rec });
                    p += real;
                }
                None => p += 4,
            }
        }
    }

    fn stale_at(&self, block: &[u8], p: usize, to: usize) -> Option<(DirRecord, usize)> {
        let (inode, rec_len, name_len, file_type) = self.header(block, p)?;
        let real = (HEADER + name_len).next_multiple_of(4);
        let plausible = inode != 0
            && inode <= self.max_inode
            && name_len > 0
            && name_len <= 255
            && p + HEADER + name_len <= to
            && rec_len >= real
            && rec_len.is_multiple_of(4)
            && p + rec_len <= block.len()
            && file_type <= MAX_FILE_TYPE;
        if !plausible {
            return None;
        }
        let name = block.get(p + HEADER..p + HEADER + name_len)?;
        (valid_name(name) && name != b"." && name != b"..").then(|| (record(inode, name, file_type, true, 0), real))
    }
}

fn record(inode: u32, name: &[u8], file_type: u8, deleted: bool, offset: u64) -> DirRecord {
    DirRecord { inode, name: String::from_utf8_lossy(name).into_owned(), file_type, deleted, offset }
}

/// Slack is arbitrary bytes: accept only printable UTF-8 names without `/`.
fn valid_name(name: &[u8]) -> bool {
    std::str::from_utf8(name).is_ok_and(|s| !s.is_empty() && s.chars().all(|c| c != '/' && !c.is_control()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirent(inode: u32, rec_len: u16, name: &str, ftype: u8) -> Vec<u8> {
        let mut e = inode.to_le_bytes().to_vec();
        e.extend(rec_len.to_le_bytes());
        e.push(name.len() as u8);
        e.push(ftype);
        e.extend(name.as_bytes());
        e.resize((8 + name.len()).next_multiple_of(4), 0);
        e
    }

    #[test]
    fn live_entries_and_deleted_slack() {
        let mut b = dirent(2, 12, ".", 2);
        b.extend(dirent(2, 12, "..", 2));
        // "keep" absorbed the deleted "gone.txt" (rec_len 12 + 16).
        b.extend(dirent(12, 28, "keep", 1));
        b.extend(dirent(13, 16, "gone.txt", 1));
        let rest = 1024 - b.len() as u16;
        b.extend(dirent(14, rest, "last", 1));
        b.resize(1024, 0);
        let recs = DirParser::new(true, 100).parse(&[(4096, &b)], false);
        let names: Vec<(&str, bool, u32)> = recs.iter().map(|r| (r.name.as_str(), r.deleted, r.inode)).collect();
        assert_eq!(names, vec![("keep", false, 12), ("gone.txt", true, 13), ("last", false, 14)]);
        assert_eq!(recs[1].offset, 4096 + 36);
    }

    #[test]
    fn dx_root_and_nodes_are_skipped() {
        let mut root = dirent(2, 12, ".", 2);
        root.extend(dirent(2, 1012, "..", 2));
        root.extend([0, 0, 0, 0, 8, 0, 0, 0, 0xFF, 0x7F, 1, 0, 9, 0, 0, 0]);
        root.resize(1024, 0x41);
        let mut node = vec![0u8; 1024];
        node[4..6].copy_from_slice(&1024u16.to_le_bytes());
        node[8..].fill(0x33);
        let recs = DirParser::new(true, 100).parse(&[(0, &root), (1024, &node)], true);
        assert!(recs.is_empty(), "{recs:?}");
    }

    #[test]
    fn garbage_never_panics() {
        let p = DirParser::new(true, u32::MAX);
        for seed in 0..64u64 {
            let data = crate::testutil::noise(1024, seed);
            let _ = p.parse(&[(0, &data)], seed % 2 == 0);
            let _ = p.parse_inline(&data[..(seed as usize * 7) % 100], 0);
        }
    }
}
