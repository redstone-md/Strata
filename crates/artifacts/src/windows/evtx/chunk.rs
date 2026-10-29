//! `ElfChnk` chunks: 64 KiB blocks holding a header, string/template tables and event records.
//! Both chunk checksums are verified; records are read even when they do not match.

use super::binxml::BinXml;
use super::record::EventRecord;
use crate::text::filetime_at;
use strata_kernel::bytes::{u32_le, u64_le};
use strata_kernel::{ByteRange, Damage, DamageKind};

pub(super) const CHUNK_SIG: &[u8; 8] = b"ElfChnk\0";
pub(super) const CHUNK_SIZE: usize = 0x10000;
const HEADER_SIZE: usize = 0x200;
const RECORD_SIG: &[u8; 4] = b"\x2a\x2a\x00\x00";
const RECORD_HEADER: usize = 24;

/// Records recovered from one chunk.
pub(super) struct ChunkRecords {
    pub(super) records: Vec<EventRecord>,
    pub(super) damage: Vec<Damage>,
}

/// Parse the chunk starting at `data[0]`; `base` is its offset in the evidence buffer (for
/// damage ranges). `data` may be shorter than 64 KiB (truncated or carved).
pub(super) fn parse(data: &[u8], base: u64) -> ChunkRecords {
    let chunk = &data[..data.len().min(CHUNK_SIZE)];
    let mut out = ChunkRecords { records: Vec::new(), damage: Vec::new() };
    let at = |off: usize, len: usize| Some(ByteRange::new(base + off as u64, len as u64));
    if chunk.len() < CHUNK_SIZE {
        out.damage.push(Damage::new(DamageKind::Truncated, at(0, chunk.len()), "EVTX chunk truncated"));
    }
    if !header_checksum_ok(chunk) {
        out.damage.push(Damage::new(DamageKind::Corrupt, at(0, HEADER_SIZE), "EVTX chunk header checksum mismatch"));
    }
    let free = u32_le(chunk, 48).map_or(chunk.len(), |f| f as usize);
    let end = if (HEADER_SIZE..=chunk.len()).contains(&free) {
        if chunk.get(HEADER_SIZE..free).is_some_and(|r| u32_le(chunk, 52) != Some(crc32fast::hash(r))) {
            out.damage.push(Damage::new(DamageKind::Corrupt, at(HEADER_SIZE, free - HEADER_SIZE), "EVTX chunk records checksum mismatch"));
        }
        free
    } else {
        out.damage.push(Damage::new(DamageKind::Corrupt, at(48, 4), "EVTX chunk free-space offset invalid; scanning whole chunk"));
        chunk.len()
    };
    let mut xml = BinXml::new(chunk);
    let mut pos = HEADER_SIZE;
    while pos + RECORD_HEADER <= end {
        if chunk.get(pos..pos + 4) != Some(RECORD_SIG) {
            // Resynchronise on the next record signature (records are 8-byte aligned).
            match (pos + 8..end.saturating_sub(RECORD_HEADER)).step_by(8).find(|p| chunk.get(*p..*p + 4) == Some(RECORD_SIG)) {
                Some(next) => {
                    out.damage.push(Damage::corrupt(
                        ByteRange::new(base + pos as u64, (next - pos) as u64),
                        "EVTX bytes between records skipped",
                    ));
                    pos = next;
                }
                None => break,
            }
        }
        let size = u32_le(chunk, pos + 4).map_or(0, |s| s as usize);
        let valid = size >= RECORD_HEADER + 4 && pos + size <= end && u32_le(chunk, pos + size - 4) == Some(size as u32);
        if !valid {
            out.damage.push(Damage::corrupt(ByteRange::new(base + pos as u64, 8), "EVTX record size invalid"));
            pos += 8;
            continue;
        }
        let id = u64_le(chunk, pos + 8).unwrap_or(0);
        let written = filetime_at(chunk, pos + 16);
        let nodes = xml.fragment(pos + RECORD_HEADER, pos + size - 4);
        match EventRecord::from_nodes(id, written, &nodes) {
            Some(r) => out.records.push(r),
            None => out
                .damage
                .push(Damage::corrupt(ByteRange::new(base + pos as u64, size as u64), format!("EVTX record {id}: event XML unreadable"))),
        }
        pos += size;
    }
    out
}

/// CRC32 of header bytes 0..120 and 128..512, stored at 124.
fn header_checksum_ok(chunk: &[u8]) -> bool {
    match (chunk.get(..120), chunk.get(128..HEADER_SIZE), u32_le(chunk, 124)) {
        (Some(a), Some(b), Some(stored)) => {
            let mut h = crc32fast::Hasher::new();
            h.update(a);
            h.update(b);
            h.finalize() == stored
        }
        _ => false,
    }
}
