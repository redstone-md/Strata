//! Test-only builder for synthetic little-endian BDB btree files.

use super::page::{B_KEYDATA, B_OVERFLOW, HEADER_LEN, MAGIC_BTREE, P_BTREEMETA, P_LBTREE, P_OVERFLOW};

pub(crate) struct BdbBuilder {
    page_size: usize,
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BdbBuilder {
    pub fn new(page_size: usize) -> Self {
        Self { page_size, records: Vec::new() }
    }

    pub fn record(mut self, key: &[u8], value: &[u8]) -> Self {
        self.records.push((key.to_vec(), value.to_vec()));
        self
    }

    /// Meta page, leaf pages (records packed in order), overflow pages for large values.
    pub fn build(self) -> Vec<u8> {
        let ps = self.page_size;
        let inline_max = ps / 4;
        let mut leaves: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
        let mut overflow_pages: Vec<Vec<u8>> = Vec::new();
        // Placeholder for overflow page numbers: assigned after leaf count is known.
        let mut pending: Vec<(usize, usize, Vec<u8>)> = Vec::new();
        let mut used = HEADER_LEN;
        for (k, v) in &self.records {
            let mut items = Vec::new();
            for data in [k, v] {
                if data.len() > inline_max {
                    let mut item = vec![0u8; 12];
                    item[2] = B_OVERFLOW;
                    item[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
                    items.push(item);
                    pending.push((leaves.len() - 1, 0, data.clone()));
                } else {
                    let mut item = (data.len() as u16).to_le_bytes().to_vec();
                    item.push(B_KEYDATA);
                    item.extend_from_slice(data);
                    items.push(item);
                }
            }
            let need: usize = items.iter().map(|i| i.len() + 2 + 4).sum();
            if used + need > ps {
                leaves.push(Vec::new());
                used = HEADER_LEN;
                if let Some(last) = pending.last_mut() {
                    last.0 = leaves.len() - 1;
                }
            }
            used += need;
            if let Some(leaf) = leaves.last_mut() {
                leaf.extend(items);
            }
        }
        let first_overflow = 1 + leaves.len();
        let mut next_free = first_overflow;
        let mut overflow_starts = Vec::new();
        for (_, _, data) in &pending {
            overflow_starts.push(next_free as u32);
            let chunks: Vec<&[u8]> = data.chunks(ps - HEADER_LEN).collect();
            for (ci, chunk) in chunks.iter().enumerate() {
                let mut page = vec![0u8; ps];
                let pgno = next_free as u32;
                page[8..12].copy_from_slice(&pgno.to_le_bytes());
                let next = if ci + 1 < chunks.len() { pgno + 1 } else { 0 };
                page[16..20].copy_from_slice(&next.to_le_bytes());
                page[22..24].copy_from_slice(&(chunk.len() as u16).to_le_bytes());
                page[25] = P_OVERFLOW;
                page[HEADER_LEN..HEADER_LEN + chunk.len()].copy_from_slice(chunk);
                overflow_pages.push(page);
                next_free += 1;
            }
        }
        let total_pages = next_free;
        let mut out = vec![0u8; ps];
        out[12..16].copy_from_slice(&MAGIC_BTREE.to_le_bytes());
        out[16..20].copy_from_slice(&9u32.to_le_bytes());
        out[20..24].copy_from_slice(&(ps as u32).to_le_bytes());
        out[25] = P_BTREEMETA;
        out[32..36].copy_from_slice(&((total_pages - 1) as u32).to_le_bytes());
        let mut ov = overflow_starts.into_iter();
        for (li, items) in leaves.iter().enumerate() {
            let mut page = vec![0u8; ps];
            page[8..12].copy_from_slice(&((li + 1) as u32).to_le_bytes());
            page[20..22].copy_from_slice(&(items.len() as u16).to_le_bytes());
            page[25] = P_LBTREE;
            let mut top = ps;
            for (ii, item) in items.iter().enumerate() {
                let mut item = item.clone();
                if item.get(2) == Some(&B_OVERFLOW) && item.len() == 12 {
                    let pg = ov.next().unwrap_or(0);
                    item[4..8].copy_from_slice(&pg.to_le_bytes());
                }
                top = (top - item.len()) & !3;
                page[top..top + item.len()].copy_from_slice(&item);
                let idx = HEADER_LEN + 2 * ii;
                page[idx..idx + 2].copy_from_slice(&(top as u16).to_le_bytes());
            }
            out.extend(page);
        }
        for page in overflow_pages {
            out.extend(page);
        }
        out
    }
}
