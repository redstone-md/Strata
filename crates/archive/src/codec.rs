//! Shared decoding helpers: panic guard around third-party decoders and bounded, partial-output
//! stream reading.

use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use strata_kernel::{Damage, DamageKind, Error, Result};

const CHUNK: usize = 256 * 1024;

/// Run a third-party parser/decoder on hostile bytes; a panic becomes an error.
pub(crate) fn guarded<T>(what: &str, f: impl FnOnce() -> T) -> Result<T> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|_| Error::format(format!("{what}: decoder failed on malformed data")))
}

/// Bytes decoded from one stream, with what went wrong.
#[derive(Debug, Default)]
pub(crate) struct Decoded {
    pub data: Vec<u8>,
    pub damage: Vec<Damage>,
    /// The stream ended cleanly (not cut by `limit` or an error).
    pub complete: bool,
}

impl Decoded {
    pub fn into_parts(self) -> (Vec<u8>, Vec<Damage>) {
        (self.data, self.damage)
    }
}

/// Read `r` to its end, keeping at most `limit` bytes; errors keep what was produced so far.
pub(crate) fn read_limited(mut r: impl Read, limit: usize, what: &str) -> Decoded {
    let mut out = Decoded::default();
    let mut buf = vec![0u8; CHUNK];
    loop {
        if out.data.len() >= limit {
            // One more byte tells "exactly at the limit" from "cut".
            let mut probe = [0u8; 1];
            if matches!(r.read(&mut probe), Ok(n) if n > 0) {
                out.damage.push(Damage::new(
                    DamageKind::Missing,
                    None,
                    format!("{what}: output capped at {limit} bytes"),
                ));
                return out;
            }
            out.complete = true;
            return out;
        }
        let want = CHUNK.min(limit - out.data.len());
        match r.read(&mut buf[..want]) {
            Ok(0) => {
                out.complete = true;
                return out;
            }
            Ok(n) => out.data.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                let kind = if e.kind() == std::io::ErrorKind::UnexpectedEof { DamageKind::Truncated } else { DamageKind::Corrupt };
                out.damage.push(Damage::new(kind, None, format!("{what}: {e} after {} bytes", out.data.len())));
                return out;
            }
        }
    }
}

/// [`read_limited`] behind the panic guard; a panic keeps nothing but is reported.
pub(crate) fn decode_guarded<R: Read>(what: &str, limit: usize, make: impl FnOnce() -> std::io::Result<R>) -> Decoded {
    let run = guarded(what, || match make() {
        Ok(r) => read_limited(r, limit, what),
        Err(e) => Decoded { damage: vec![Damage::new(DamageKind::Corrupt, None, format!("{what}: {e}"))], ..Decoded::default() },
    });
    run.unwrap_or_else(|e| Decoded { damage: vec![Damage::new(DamageKind::Corrupt, None, e.to_string())], ..Decoded::default() })
}

pub(crate) fn gzip(input: &[u8], limit: usize) -> Decoded {
    decode_guarded("gzip", limit, || Ok(flate2::read::MultiGzDecoder::new(input)))
}

pub(crate) fn bzip2(input: &[u8], limit: usize) -> Decoded {
    decode_guarded("bzip2", limit, || Ok(bzip2::read::MultiBzDecoder::new(input)))
}

pub(crate) fn xz(input: &[u8], limit: usize) -> Decoded {
    decode_guarded("xz", limit, || Ok(lzma_rust2::XzReader::new(input, true)))
}

/// ZIP method 14: 2-byte version, 2-byte properties size, properties, raw LZMA.
pub(crate) fn zip_lzma(input: &[u8], size: u64, limit: usize) -> Decoded {
    decode_guarded("lzma", limit, || {
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "short LZMA header");
        let props_len = usize::from(u16::from_le_bytes([*input.get(2).ok_or_else(bad)?, *input.get(3).ok_or_else(bad)?]));
        let props = input.get(4..4 + props_len).filter(|p| p.len() >= 5).ok_or_else(bad)?;
        let dict = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
        let body = input.get(4 + props_len..).unwrap_or_default();
        lzma_rust2::LzmaReader::new_with_props(body, size, props[0], dict, None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_output_and_reports_it() {
        let d = read_limited(&[7u8; 1000][..], 100, "t");
        assert_eq!(d.data.len(), 100);
        assert!(!d.complete);
        assert_eq!(d.damage.len(), 1);
        let d = read_limited(&[7u8; 100][..], 100, "t");
        assert!(d.complete && d.damage.is_empty());
    }

    #[test]
    fn garbage_never_panics() {
        let junk: Vec<u8> = (0..5000u32).map(|i| (i * 7919 % 251) as u8).collect();
        for f in [gzip, bzip2, xz] {
            let d = f(&junk, 1 << 20);
            assert!(!d.complete || d.data.is_empty());
        }
        assert!(zip_lzma(&junk, 100, 1000).data.len() <= 1000);
    }
}
