//! Structure scanners for images and media.

use super::graded;
use crate::probe::Probe;
use crate::registry::TypeId;
use memchr::memmem;
use strata_kernel::Confidence;
use strata_kernel::bytes::{u16_be, u32_be};

/// JPEG: table/frame/scan markers with sane lengths, or the byte-stuffing signature of
/// entropy-coded data (every 0xFF followed by 0x00 or a restart marker).
pub fn jpeg(data: &[u8]) -> Option<Probe> {
    let mut kinds = 0;
    let mut dims = None;
    for marker in [[0xFFu8, 0xDB], [0xFF, 0xC4], [0xFF, 0xC0], [0xFF, 0xC2], [0xFF, 0xDA]] {
        let found = memmem::find_iter(data, &marker).take(256).find(|p| {
            let len = u16_be(data, p + 2).unwrap_or(0);
            match marker[1] {
                0xDB => len > 2 && (len - 2).is_multiple_of(65),
                0xC4 => (20..=420).contains(&len),
                0xC0 | 0xC2 => matches!(len, 11 | 17) && data.get(p + 4) == Some(&8),
                _ => matches!(len, 8 | 10 | 12) && data.get(p + 4).is_some_and(|n| (1..=3).contains(n)),
            }
        });
        if let Some(p) = found {
            kinds += 1;
            if matches!(marker[1], 0xC0 | 0xC2) {
                dims = Some((u16_be(data, p + 7).unwrap_or(0), u16_be(data, p + 5).unwrap_or(0)));
            }
        }
    }
    let (ff, stuffed) = memchr::memchr_iter(0xFF, data)
        .filter_map(|p| data.get(p + 1))
        .fold((0usize, 0usize), |(n, s), next| (n + 1, s + usize::from(matches!(next, 0x00 | 0xD0..=0xD7 | 0xD9))));
    let stuffing = ff >= 32 && stuffed * 10 >= ff * 9;
    if kinds < 2 && !stuffing {
        return None;
    }
    let c = if kinds >= 2 { graded(0.5, 0.25, kinds, 5) } else { Confidence::new(0.5) };
    let mut p = Probe::new(TypeId::Jpeg, Confidence::new(c.get() + if stuffing { 0.05 } else { 0.0 }));
    if stuffing {
        p.note(format!("entropy-coded scan data recognised ({stuffed}/{ff} byte-stuffed 0xFF)"));
    }
    if let Some((w, h)) = dims {
        p.property("dimensions", format!("{w}x{h}"));
    }
    if kinds < 2 {
        p.note("JPEG tables lost: image data present but not decodable without a donor header");
        p = p.with_structure(0.5);
    }
    Some(p)
}

/// PNG: chunks whose CRC verifies.
pub fn png(data: &[u8]) -> Option<Probe> {
    let mut good = 0;
    for kind in [b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tEXt", b"pHYs"] {
        for at in memmem::find_iter(data, kind).take(64) {
            let Some(start) = at.checked_sub(4) else { continue };
            let Some(len) = u32_be(data, start).map(|l| l as usize).filter(|l| *l < 1 << 24) else { continue };
            let body = data.get(at..at + 4 + len);
            if body.is_some_and(|b| u32_be(data, at + 4 + len) == Some(crc32fast::hash(b))) {
                good += 1;
            }
        }
    }
    (good >= 1).then(|| Probe::new(TypeId::Png, graded(0.5, 0.3, good, 4)))
}

/// ISO BMFF: nested box headers with consistent sizes.
pub fn mp4(data: &[u8]) -> Option<Probe> {
    let mut good = 0;
    for kind in [b"moov", b"mvhd", b"trak", b"stbl", b"mdat", b"ftyp"] {
        good += memmem::find_iter(data, kind)
            .take(16)
            .filter(|at| at.checked_sub(4).and_then(|s| u32_be(data, s)).is_some_and(|size| size >= 8))
            .count()
            .min(1);
    }
    (good >= 3).then(|| Probe::new(TypeId::Mp4, graded(0.4, 0.3, good, 6)))
}
