//! Block reads for the ext parser: single blocks, runs, and batches merged into few large reads
//! (bitmaps and inode tables of flex groups sit next to each other on disk).

use super::superblock::Superblock;
use strata_source::BlockSource;

/// Largest single read when merging neighbouring blocks.
const MAX_MERGED: u64 = 16 << 20;

pub(super) struct BlockReader<'a> {
    source: &'a dyn BlockSource,
    sb: &'a Superblock,
}

impl<'a> BlockReader<'a> {
    pub(super) fn new(source: &'a dyn BlockSource, sb: &'a Superblock) -> Self {
        Self { source, sb }
    }

    pub(super) fn sb(&self) -> &'a Superblock {
        self.sb
    }

    pub(super) fn source(&self) -> &'a dyn BlockSource {
        self.source
    }

    /// `count` blocks from `block`; `None` if outside the filesystem or short.
    pub(super) fn blocks(&self, block: u64, count: u64) -> Option<Vec<u8>> {
        let end = block.checked_add(count)?;
        if count == 0 || end > self.sb.blocks_count() {
            return None;
        }
        let len = usize::try_from(count.checked_mul(self.sb.block_size())?).ok()?;
        let data = self.source.read_vec(self.sb.block_offset(block)?, len).ok()?;
        (data.len() == len).then_some(data)
    }

    pub(super) fn block(&self, block: u64) -> Option<Vec<u8>> {
        self.blocks(block, 1)
    }

    /// Read many `(block, count)` runs, merging physically adjacent ones. Results keep the
    /// input order; unreadable runs are `None`.
    pub(super) fn batch(&self, runs: &[(u64, u64)]) -> Vec<Option<Vec<u8>>> {
        let bs = self.sb.block_size();
        let mut order: Vec<usize> = (0..runs.len()).collect();
        order.sort_by_key(|&i| runs[i].0);
        let mut out: Vec<Option<Vec<u8>>> = vec![None; runs.len()];
        let mut i = 0;
        while i < order.len() {
            let (start, mut end) = (runs[order[i]].0, runs[order[i]].0.saturating_add(runs[order[i]].1));
            let mut j = i + 1;
            while j < order.len() {
                let (s, c) = runs[order[j]];
                if s != end || (s.saturating_add(c) - start) * bs > MAX_MERGED {
                    break;
                }
                end = s.saturating_add(c);
                j += 1;
            }
            let merged = self.blocks(start, end - start);
            for &k in &order[i..j] {
                let (s, c) = runs[k];
                out[k] = match &merged {
                    Some(data) => data.get(((s - start) * bs) as usize..((s - start + c) * bs) as usize).map(<[u8]>::to_vec),
                    None => self.blocks(s, c),
                };
            }
            i = j;
        }
        out
    }
}
