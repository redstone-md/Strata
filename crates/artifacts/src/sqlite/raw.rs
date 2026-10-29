//! Best-effort URL extraction from raw database bytes (damaged SQLite files, freelist pages,
//! unallocated page space): URL-looking strings plus the nearest plausible 8-byte timestamp.

use crate::text::is_url;
use strata_kernel::Timestamp;
use strata_kernel::bytes::i64_be;

/// How an 8-byte big-endian integer near a URL is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeEncoding {
    /// Chrome: µs since 1601.
    Webkit,
    /// Firefox PRTime: µs since 1970.
    PrTime,
}

impl TimeEncoding {
    fn decode(self, v: i64) -> Option<Timestamp> {
        let ts = match self {
            Self::Webkit => Timestamp::from_webkit(v),
            Self::PrTime => Timestamp::from_unix_micros(v),
        }?;
        // Raw hits are guesses; keep them to the era browsers with these formats existed.
        let year = ts.civil().0;
        (1996..=2035).contains(&year).then_some(ts)
    }
}

/// A URL found in raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawUrl {
    pub offset: usize,
    pub url: String,
    pub time: Option<Timestamp>,
}

pub(crate) struct RawUrlScanner {
    encoding: TimeEncoding,
    /// Bytes searched on each side of the URL for a timestamp.
    window: usize,
}

const SCHEMES: [&[u8]; 4] = [b"http://", b"https://", b"ftp://", b"file://"];
const MAX_URL: usize = 2048;

impl RawUrlScanner {
    pub fn new(encoding: TimeEncoding) -> Self {
        Self { encoding, window: 96 }
    }

    /// Every URL in `data[start..end]` (clamped), offsets absolute in `data`.
    pub fn scan(&self, data: &[u8], start: usize, end: usize) -> Vec<RawUrl> {
        let end = end.min(data.len());
        let mut out = Vec::new();
        let mut i = start;
        while i < end {
            let Some(rel) = find_scheme(data.get(i..end).unwrap_or(&[])) else { break };
            let at = i + rel;
            let run = data[at..end].iter().take(MAX_URL).take_while(|b| is_url_byte(**b)).count();
            let len = record_text_len(data, at, run).unwrap_or(run);
            if let Ok(url) = std::str::from_utf8(&data[at..at + len])
                && is_url(url)
            {
                out.push(RawUrl { offset: at, url: url.to_string(), time: self.nearby_time(data, at, at + len) });
            }
            i = at + len.max(1);
        }
        out
    }

    /// Closest plausible timestamp, preferring bytes after the URL (record column order puts
    /// times after the URL/title in both Chrome `urls` and Firefox `moz_places`).
    fn nearby_time(&self, data: &[u8], url_start: usize, url_end: usize) -> Option<Timestamp> {
        let after = (url_end..url_end.saturating_add(self.window * 2)).map(|o| (o - url_end, o));
        let before = (url_start.saturating_sub(self.window)..url_start).rev().map(|o| (url_start - o + self.window, o));
        let mut best: Option<(usize, Timestamp)> = None;
        for (dist, off) in after.chain(before) {
            if let Some(ts) = i64_be(data, off).and_then(|v| self.encoding.decode(v))
                && best.is_none_or(|(d, _)| dist < d)
            {
                best = Some((dist, ts));
            }
        }
        best.map(|(_, ts)| ts)
    }
}

/// SQLite packs record values back to back, so a URL is often glued to the following title.
/// When the record header survives intact right before the URL (header length `h` at
/// `at - h`), its first text serial type (`2n + 13`) gives the exact URL length; the URL is
/// the first text column in both Chrome `urls` and Firefox `moz_places`.
fn record_text_len(data: &[u8], at: usize, run: usize) -> Option<usize> {
    (at.saturating_sub(64)..at).rev().find_map(|h| {
        let (hdr_len, used) = varint(data, h)?;
        if usize::try_from(hdr_len).ok()? != at - h || hdr_len < 2 {
            return None;
        }
        let mut types = Vec::new();
        let mut p = h + used;
        while p < at {
            let (t, n) = varint(data, p)?;
            if t == 10 || t == 11 {
                return None;
            }
            types.push(t);
            p += n;
        }
        let t = *types.iter().find(|t| **t >= 13 && **t % 2 == 1)?;
        let len = usize::try_from((t - 13) / 2).ok()?;
        let url = std::str::from_utf8(data.get(at..at + len)?).ok()?;
        (p == at && len <= run && is_url(url)).then_some(len)
    })
}

/// SQLite big-endian varint (1..=9 bytes) → (value, bytes used).
fn varint(data: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let b = *data.get(off + i)?;
        if i == 8 {
            return Some(((v << 8) | u64::from(b), 9));
        }
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn find_scheme(hay: &[u8]) -> Option<usize> {
    // memchr-free: scan for 'h'/'f' starts; inputs are pages, so this is cheap enough.
    hay.iter().enumerate().find_map(|(i, &b)| {
        ((b == b'h' || b == b'f') && SCHEMES.iter().any(|s| hay[i..].starts_with(s))).then_some(i)
    })
}

fn is_url_byte(b: u8) -> bool {
    (0x21..0x7f).contains(&b) && b != b'"' && b != b'<' && b != b'>' && b != b'\''
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_url_and_time() {
        // Chrome-like record tail: url, title, then 8-byte webkit time (2011-05-14 17:36:09).
        let webkit: i64 = (1_305_394_569 + 11_644_473_600) * 1_000_000;
        let url = b"https://bitcointalk.org/index.php";
        let mut data = vec![0u8; 18];
        // Record header: hdr_len, NULL rowid alias, url text type, title text type.
        data.extend_from_slice(&[4, 0, (url.len() * 2 + 13) as u8, (14 * 2 + 13) as u8]);
        data.extend_from_slice(url);
        data.extend_from_slice(b"Bitcoin Forum\x01");
        data.extend_from_slice(&webkit.to_be_bytes());
        data.extend_from_slice(b"\x00\x00ftp://x");
        let hits = RawUrlScanner::new(TimeEncoding::Webkit).scan(&data, 0, data.len());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://bitcointalk.org/index.php");
        assert_eq!(hits[0].time.unwrap().to_string(), "2011-05-14 17:36:09");
    }

    #[test]
    fn garbage_and_bounds() {
        let s = RawUrlScanner::new(TimeEncoding::PrTime);
        assert!(s.scan(b"http://", 0, 100).is_empty());
        assert!(s.scan(b"", 5, 1).is_empty());
        let junk: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7919) % 256) as u8).collect();
        let _ = s.scan(&junk, 0, junk.len());
    }
}
