//! Raw-deflate stream measurement over any [`ByteView`] (ZIP members, GZIP members).

use crate::view::ByteView;
use flate2::{Decompress, FlushDecompress, Status};

/// Stop measuring a stream after this much output (decompression bombs).
const MEASURE_CAP: u64 = 4 << 30;
const IN_CHUNK: usize = 1 << 20;

/// Outcome of running a deflate stream to its end without keeping the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateRun {
    /// Compressed bytes consumed.
    pub consumed: u64,
    /// Decompressed bytes produced.
    pub produced: u64,
    /// The final block was reached cleanly.
    pub complete: bool,
    /// The stream is invalid (as opposed to merely running out of input).
    pub invalid: bool,
}

/// Inflate the raw deflate stream starting at `start` in `view`.
pub fn measure_deflate(view: &dyn ByteView, start: u64) -> DeflateRun {
    let mut z = Decompress::new(false);
    let mut scratch = vec![0u8; 256 * 1024];
    let mut chunk_at = start;
    let mut chunk = view.bytes(chunk_at, IN_CHUNK);
    let mut invalid = false;
    loop {
        let pos = start + z.total_in();
        let used = (pos - chunk_at) as usize;
        // Keep at least 64 KiB of input available unless the view is exhausted.
        if chunk.len() == IN_CHUNK && chunk.len() - used.min(chunk.len()) < 64 * 1024 {
            chunk_at = pos;
            chunk = view.bytes(chunk_at, IN_CHUNK);
            continue;
        }
        let input = chunk.get(used..).unwrap_or_default();
        let (before_in, before_out) = (z.total_in(), z.total_out());
        match z.decompress(input, &mut scratch, FlushDecompress::None) {
            Ok(Status::StreamEnd) => {
                return DeflateRun { consumed: z.total_in(), produced: z.total_out(), complete: true, invalid: false };
            }
            Ok(_) if z.total_in() == before_in && z.total_out() == before_out => break,
            Ok(_) if z.total_out() > MEASURE_CAP => break,
            Ok(_) => {}
            Err(_) => {
                invalid = true;
                break;
            }
        }
    }
    DeflateRun { consumed: z.total_in(), produced: z.total_out(), complete: false, invalid }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    #[test]
    fn measures_stream_and_stops_at_end() {
        let plain: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&plain).unwrap();
        let mut packed = enc.finish().unwrap();
        let n = packed.len() as u64;
        packed.extend_from_slice(b"TRAILING GARBAGE");
        let run = measure_deflate(&packed.as_slice(), 0);
        assert_eq!(run, DeflateRun { consumed: n, produced: plain.len() as u64, complete: true, invalid: false });
        let cut = &packed[..(n / 2) as usize];
        assert!(!measure_deflate(&cut, 0).complete);
    }
}
