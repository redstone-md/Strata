//! Windows Vista+ event logs (`.evtx`): file header, 64 KiB `ElfChnk` chunks with CRC checks,
//! event records in Binary XML. Without a file header (carved, partly overwritten) the buffer is
//! scanned for chunk signatures instead.

mod binxml;
mod chunk;
mod mapping;
mod record;
mod value;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

use crate::results::Recorder;
use chunk::{CHUNK_SIG, CHUNK_SIZE};
use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, DamageKind};

const FILE_SIG: &[u8; 8] = b"ElfFile\0";
const FILE_HEADER_BLOCK: usize = 0x1000;

pub(crate) struct Evtx;

impl Evtx {
    /// A log file, or a bare chunk (carved).
    pub fn is_evtx(data: &[u8]) -> bool {
        data.starts_with(FILE_SIG) || data.starts_with(CHUNK_SIG)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        if !data.starts_with(FILE_SIG) {
            Self::carve(data, rec);
            return;
        }
        if u32_le(data, 124) != data.get(..120).map(crc32fast::hash) {
            rec.damage(Damage::corrupt(ByteRange::new(0, 128), "EVTX file header checksum mismatch"));
        }
        let declared = usize::from(u16_le(data, 42).unwrap_or(0));
        // Dirty logs hold more chunks than the header admits: look at every slot.
        let slots = data.len().saturating_sub(FILE_HEADER_BLOCK).div_ceil(CHUNK_SIZE);
        for i in 0..slots {
            let off = FILE_HEADER_BLOCK + i * CHUNK_SIZE;
            let Some(bytes) = data.get(off..) else { break };
            if bytes.starts_with(CHUNK_SIG) {
                Self::chunk(bytes, off, rec, true);
            } else if i < declared {
                let range = ByteRange::new(off as u64, bytes.len().min(CHUNK_SIZE) as u64);
                rec.damage(Damage::new(DamageKind::Missing, Some(range), format!("EVTX chunk {i} missing or overwritten")));
            }
        }
    }

    /// Scan any buffer (free space, a damaged file) for chunk signatures.
    pub fn carve(data: &[u8], rec: &mut Recorder) {
        let mut pos = 0;
        while let Some(rel) = data.get(pos..).and_then(|d| d.windows(CHUNK_SIG.len()).position(|w| w == CHUNK_SIG)) {
            let off = pos + rel;
            let parsed = Self::chunk(&data[off..], off, rec, false);
            pos = off + if parsed { CHUNK_SIZE } else { CHUNK_SIG.len() };
        }
    }

    /// Parse one chunk; `true` when it yielded records. Carved signatures that yield nothing are
    /// coincidences, not damage, unless `report_empty`.
    fn chunk(bytes: &[u8], off: usize, rec: &mut Recorder, report_empty: bool) -> bool {
        let parsed = chunk::parse(bytes, off as u64);
        if parsed.records.is_empty() && !report_empty {
            return false;
        }
        for d in parsed.damage {
            rec.damage(d);
        }
        for r in &parsed.records {
            mapping::emit(r, rec);
        }
        !parsed.records.is_empty()
    }
}
