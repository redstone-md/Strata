//! Sweep free space for stray `FILE` records (left by an old, moved or reformatted `$MFT`).

use super::boot::NtfsBoot;
use super::record::MftRecord;
use crate::Extent;
use strata_kernel::ByteRange;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_source::BlockSource;

const CHUNK: usize = 4 << 20;
const MAX_RECORDS: usize = 1_000_000;
/// Free space after the live `$MFT` read without finding a record before the search for an
/// older `$MFT` stops.
const OLD_MFT_GAP: u64 = 64 << 20;

/// Records found in `ranges`, with their volume offsets.
pub(super) fn carve(source: &dyn BlockSource, boot: &NtfsBoot, ranges: &[ByteRange]) -> Vec<(MftRecord, u64)> {
    sweep(source, boot, ranges, None)
}

/// Records of an older `$MFT` in the free space from where the live one starts. A quick
/// format writes a small new `$MFT` at the same place and leaves the old records right
/// behind it, so the search reads on until it has seen [`OLD_MFT_GAP`] bytes without one.
pub(super) fn after_mft(source: &dyn BlockSource, boot: &NtfsBoot, mft: &[Extent], free: &[ByteRange]) -> Vec<(MftRecord, u64)> {
    let Some(start) = mft.iter().filter_map(|e| e.volume_offset).min() else { return Vec::new() };
    let ranges: Vec<ByteRange> = free
        .iter()
        .filter(|r| r.end() > start)
        .map(|r| ByteRange::new(r.start().max(start), r.end() - r.start().max(start)))
        .collect();
    sweep(source, boot, &ranges, Some(start))
}

/// Read `ranges` in order for records. With `gap_from`, stop once [`OLD_MFT_GAP`] bytes past
/// the last record (or past `gap_from`) held none.
fn sweep(source: &dyn BlockSource, boot: &NtfsBoot, ranges: &[ByteRange], gap_from: Option<u64>) -> Vec<(MftRecord, u64)> {
    let rs = boot.record_size();
    // Inside an MFT, records sit at multiples of the record size from a cluster boundary.
    let step = (rs as u64).min(boot.cluster_size()).max(512);
    let mut out = Vec::new();
    let mut last_found = gap_from;
    for range in ranges {
        let mut pos = range.start().div_ceil(step) * step;
        while pos + rs as u64 <= range.end() && out.len() < MAX_RECORDS {
            if last_found.is_some_and(|f| pos.saturating_sub(f) > OLD_MFT_GAP) {
                return out;
            }
            let len = (CHUNK as u64).min(range.end() - pos) as usize;
            let Ok(buf) = source.read_vec(pos, len) else { break };
            let mut off = 0usize;
            while off + rs <= buf.len() {
                if looks_like_record(&buf[off..off + rs], rs) {
                    let mut raw = buf[off..off + rs].to_vec();
                    let at = pos + off as u64;
                    if let Some(rec) = MftRecord::parse(&mut raw, u64::MAX, at, true) {
                        out.push((rec, at));
                        last_found = last_found.map(|_| at);
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
