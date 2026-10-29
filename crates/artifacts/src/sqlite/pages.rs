//! Raw SQLite page layout: where deleted rows can survive (freelist pages, unallocated gaps
//! and freeblocks inside b-tree leaf pages). Works on damaged files and carved fragments.

use strata_kernel::bytes::{u16_be, u32_be, u8_at};

const LEAF_TABLE: u8 = 0x0D;
const LEAF_INDEX: u8 = 0x0A;
const INTERIOR_TABLE: u8 = 0x05;
const INTERIOR_INDEX: u8 = 0x02;

/// Page geometry of a (possibly broken) SQLite file.
pub(crate) struct SqlitePages<'a> {
    data: &'a [u8],
    page_size: usize,
}

impl<'a> SqlitePages<'a> {
    /// Uses the header page size when valid, else 4096 (typical for carved fragments).
    pub fn new(data: &'a [u8]) -> Self {
        let declared = match u16_be(data, 16) {
            Some(1) => 65_536,
            Some(n) if n >= 512 && n.is_power_of_two() => usize::from(n),
            _ => 4096,
        };
        let page_size = if super::is_sqlite(data) { declared } else { 4096 };
        Self { data, page_size }
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn page_count(&self) -> usize {
        self.data.len() / self.page_size
    }

    /// Byte range of page `n` (1-based).
    fn page(&self, n: usize) -> Option<(usize, usize)> {
        let start = n.checked_sub(1)?.checked_mul(self.page_size)?;
        let end = start.checked_add(self.page_size)?;
        (end <= self.data.len()).then_some((start, end))
    }

    /// Pages on the freelist (trunk + leaf pages), from the header chain.
    pub fn freelist(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut trunk = u32_be(self.data, 32).unwrap_or(0) as usize;
        let max = self.page_count();
        let mut guard = 0;
        while trunk != 0 && trunk <= max && guard < max {
            guard += 1;
            let Some((start, _)) = self.page(trunk) else { break };
            out.push(trunk);
            let leaves = u32_be(self.data, start + 4).unwrap_or(0) as usize;
            let cap = (self.page_size / 4).saturating_sub(2);
            for i in 0..leaves.min(cap) {
                match u32_be(self.data, start + 8 + 4 * i) {
                    Some(p) if p != 0 && (p as usize) <= max => out.push(p as usize),
                    _ => {}
                }
            }
            trunk = u32_be(self.data, start).unwrap_or(0) as usize;
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Byte ranges where deleted record bytes may survive: whole freelist pages, plus the
    /// unallocated gap and the freeblocks of every b-tree page.
    pub fn slack_regions(&self) -> Vec<(usize, usize)> {
        let free = self.freelist();
        let mut out: Vec<(usize, usize)> = free.iter().filter_map(|&p| self.page(p)).collect();
        for n in 1..=self.page_count() {
            if free.binary_search(&n).is_err() {
                self.page_slack(n, &mut out);
            }
        }
        out
    }

    fn page_slack(&self, n: usize, out: &mut Vec<(usize, usize)>) {
        let Some((start, end)) = self.page(n) else { return };
        let hdr = if n == 1 { start + 100 } else { start };
        let Some(kind) = u8_at(self.data, hdr) else { return };
        let header_len = match kind {
            LEAF_TABLE | LEAF_INDEX => 8,
            INTERIOR_TABLE | INTERIOR_INDEX => 12,
            _ => return,
        };
        let cells = usize::from(u16_be(self.data, hdr + 3).unwrap_or(0));
        let content = match u16_be(self.data, hdr + 5) {
            Some(0) => 65_536,
            Some(c) => usize::from(c),
            None => return,
        };
        let gap_start = hdr + header_len + 2 * cells;
        let gap_end = (start + content).min(end);
        if gap_start + 16 < gap_end {
            out.push((gap_start, gap_end));
        }
        // Freeblock chain: (next u16, size u16), offsets relative to the page start.
        let mut fb = usize::from(u16_be(self.data, hdr + 1).unwrap_or(0));
        let mut guard = 0;
        while fb >= 4 && fb < self.page_size && guard < 512 {
            guard += 1;
            let at = start + fb;
            let size = usize::from(u16_be(self.data, at + 2).unwrap_or(0));
            if size >= 4 && at + size <= end {
                out.push((at + 4, at + size));
            }
            let next = usize::from(u16_be(self.data, at).unwrap_or(0));
            if next <= fb {
                break;
            }
            fb = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freelist_of_real_db_after_delete() {
        let sql = "PRAGMA page_size=1024; PRAGMA auto_vacuum=0; CREATE TABLE t(a TEXT);";
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(sql).unwrap();
        for i in 0..200 {
            conn.execute("INSERT INTO t VALUES (?1)", [format!("http://example{i}.com/{}", "x".repeat(40))]).unwrap();
        }
        conn.execute("DELETE FROM t WHERE rowid > 20", []).unwrap();
        let bytes = conn.serialize(rusqlite::DatabaseName::Main).unwrap().to_vec();
        let pages = SqlitePages::new(&bytes);
        assert_eq!(pages.page_size(), 1024);
        assert!(!pages.freelist().is_empty());
        assert!(!pages.slack_regions().is_empty());
    }

    #[test]
    fn garbage_is_safe() {
        for len in [0, 10, 100, 4096, 9000] {
            let junk: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let p = SqlitePages::new(&junk);
            let _ = p.slack_regions();
        }
        let mut hdr = super::super::MAGIC.to_vec();
        hdr.resize(2048, 0xFF);
        let _ = SqlitePages::new(&hdr).slack_regions();
    }
}
