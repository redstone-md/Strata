//! Sweep free space for stray `FILE` records (left by an old, moved or reformatted `$MFT`).

use super::boot::NtfsBoot;
use super::record::MftRecord;
use strata_kernel::ByteRange;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_source::BlockSource;

const CHUNK: usize = 4 << 20;
const MAX_RECORDS: usize = 1_000_000;

/// Records found in `ranges`, with their volume offsets.
pub(super) fn carve(source: &dyn BlockSource, boot: &NtfsBoot, ranges: &[ByteRange]) -> Vec<(MftRecord, u64)> {
    let rs = boot.record_size();
    // Inside an MFT, records sit at multiples of the record size from a cluster boundary.
    let step = (rs as u64).min(boot.cluster_size()).max(512);
    let mut out = Vec::new();
    for range in ranges {
        let mut pos = range.start().div_ceil(step) * step;
        while pos + rs as u64 <= range.end() && out.len() < MAX_RECORDS {
            let len = (CHUNK as u64).min(range.end() - pos) as usize;
            let Ok(buf) = source.read_vec(pos, len) else { break };
            let mut off = 0usize;
            while off + rs <= buf.len() {
                if looks_like_record(&buf[off..off + rs], rs) {
                    let mut raw = buf[off..off + rs].to_vec();
                    let at = pos + off as u64;
                    if let Some(rec) = MftRecord::parse(&mut raw, u64::MAX, at, true) {
                        out.push((rec, at));
                    }
                }
                off += step as usize;
            }
            // Continue at the first slot that did not fit whole into this chunk.
            pos += (off as u64).max(step);
        }
    }
    out
}

fn looks_like_record(raw: &[u8], rs: usize) -> bool {
    if raw.get(..4) != Some(b"FILE") {
        return false;
    }
    let usa_count = u16_le(raw, 6).map_or(0, usize::from);
    let first_attr = u16_le(raw, 0x14).map_or(0, usize::from);
    let used = u32_le(raw, 0x18).map_or(0, |u| u as usize);
    let alloc = u32_le(raw, 0x1C).map_or(0, |u| u as usize);
    usa_count == rs / 512 + 1 && alloc == rs && used <= rs && (0x30..rs).contains(&first_attr)
}
