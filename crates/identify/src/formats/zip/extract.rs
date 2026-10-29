//! Member extraction (stored + deflate) with CRC verification and partial output on damage.

use super::records::{CENTRAL_SIG, DESCRIPTOR_SIG, LOCAL_SIG};
use super::{ZipArchive, ZipEntry};
use crate::formats::deflate::measure_deflate;
use flate2::{Decompress, FlushDecompress, Status};
use memchr::memmem;
use strata_kernel::bytes::u32_le;
use strata_kernel::{ByteRange, Damage, DamageKind};

/// Result of extracting one member. `data` holds whatever could be recovered.
#[derive(Debug, Clone)]
pub struct Extracted {
    pub data: Vec<u8>,
    /// `Some(true)` when the CRC matched, `None` when it could not be checked.
    pub crc_ok: Option<bool>,
    /// All declared bytes were produced.
    pub complete: bool,
    pub damage: Vec<Damage>,
}

impl Extracted {
    fn failed(damage: Damage) -> Self {
        Self { data: Vec::new(), crc_ok: None, complete: false, damage: vec![damage] }
    }

    pub fn is_intact(&self) -> bool {
        self.complete && self.crc_ok == Some(true) && self.damage.is_empty()
    }

    /// Decode one member's raw data (method 0 stored or 8 deflate) into at most `limit` bytes.
    /// `None` for other methods. The CRC is not checked here.
    pub fn decode(method: u16, input: &[u8], limit: usize) -> Option<Self> {
        match method {
            0 => Some(stored(input, limit)),
            8 => Some(inflate(input, limit)),
            _ => None,
        }
    }
}

impl ZipArchive {
    /// Extract `entry` from `data` (the same buffer it was parsed from), producing at most
    /// `limit` bytes.
    pub fn extract(&self, data: &[u8], entry: &ZipEntry, limit: usize) -> Extracted {
        let Some(start) = entry.data_start else {
            return Extracted::failed(Damage::missing(None, format!("{}: no local header", entry.name)));
        };
        if entry.is_encrypted() {
            return Extracted::failed(Damage::new(DamageKind::Missing, None, format!("{}: encrypted", entry.name)));
        }
        let declared = usize::try_from(entry.compressed_size).unwrap_or(usize::MAX);
        let available = data.len().saturating_sub(start);
        let input = data.get(start..start + declared.min(available)).unwrap_or_default();
        let mut out = match Extracted::decode(entry.method, input, limit) {
            Some(out) => out,
            None => {
                return Extracted::failed(Damage::new(
                    DamageKind::Missing,
                    None,
                    format!("{}: unsupported method {}", entry.name, entry.method_name()),
                ));
            }
        };
        if declared > available {
            out.damage.push(Damage::new(
                DamageKind::Truncated,
                Some(ByteRange::new(start as u64, entry.compressed_size)),
                format!("{}: data truncated ({} of {} bytes present)", entry.name, available, declared),
            ));
            out.complete = false;
        }
        out.complete &= out.data.len() as u64 == entry.uncompressed_size;
        if !out.complete && out.damage.is_empty() && out.data.len() < limit {
            out.damage.push(Damage::corrupt(
                ByteRange::new(start as u64, entry.compressed_size),
                format!("{}: produced {} of {} bytes", entry.name, out.data.len(), entry.uncompressed_size),
            ));
        }
        if out.complete {
            let ok = crc32fast::hash(&out.data) == entry.crc32;
            out.crc_ok = Some(ok);
            if !ok {
                out.damage.push(Damage::corrupt(
                    ByteRange::new(start as u64, entry.compressed_size),
                    format!("{}: CRC mismatch", entry.name),
                ));
            }
        }
        out
    }
}

fn stored(input: &[u8], limit: usize) -> Extracted {
    let n = input.len().min(limit);
    Extracted { data: input[..n].to_vec(), crc_ok: None, complete: n == input.len(), damage: Vec::new() }
}

/// Raw-deflate `input` into at most `limit` bytes.
fn inflate(input: &[u8], limit: usize) -> Extracted {
    let mut z = Decompress::new(false);
    let mut data = Vec::with_capacity(input.len().saturating_mul(3).min(limit).min(64 << 20));
    let mut damage = Vec::new();
    let mut complete = false;
    loop {
        if data.len() >= limit {
            break;
        }
        if data.capacity() == data.len() {
            data.reserve((data.len().max(64 * 1024)).min(limit - data.len()));
        }
        let consumed = z.total_in() as usize;
        let before = z.total_out();
        let rest = input.get(consumed..).unwrap_or_default();
        match z.decompress_vec(rest, &mut data, FlushDecompress::None) {
            Ok(Status::StreamEnd) => {
                complete = true;
                break;
            }
            Ok(_) if z.total_out() == before && z.total_in() as usize == consumed => {
                damage.push(Damage::truncated("deflate stream ends early"));
                break;
            }
            Ok(_) => {}
            Err(e) => {
                damage.push(Damage::corrupt(
                    ByteRange::new(z.total_in(), input.len() as u64 - z.total_in().min(input.len() as u64)),
                    format!("deflate error: {e}"),
                ));
                break;
            }
        }
    }
    data.truncate(limit);
    Extracted { data, crc_ok: None, complete, damage }
}

/// Members written with a data descriptor (sizes zero in the local header): find their end.
pub(super) fn resolve_descriptor(data: &[u8], entry: &mut ZipEntry) {
    let Some(start) = entry.data_start else { return };
    let rest = data.get(start..).unwrap_or_default();
    let consumed = if entry.method == 8 {
        let run = measure_deflate(&rest, 0);
        if !run.complete {
            entry.damage.push(Damage::truncated(format!("{}: deflate stream incomplete", entry.name)));
        }
        entry.uncompressed_size = run.produced;
        usize::try_from(run.consumed).ok()
    } else {
        memmem::find(rest, DESCRIPTOR_SIG)
            .or_else(|| memmem::find(rest, LOCAL_SIG))
            .or_else(|| memmem::find(rest, CENTRAL_SIG))
    };
    let Some(len) = consumed else { return };
    entry.compressed_size = len as u64;
    let desc = start + len;
    let at = if data.get(desc..desc + 4) == Some(DESCRIPTOR_SIG) { desc + 4 } else { desc };
    if let Some(crc) = u32_le(data, at) {
        entry.crc32 = crc;
    }
    if entry.method == 0
        && let Some(size) = u32_le(data, at + 8)
    {
        entry.uncompressed_size = u64::from(size);
    }
}
