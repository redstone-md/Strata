//! Images: JPEG, PNG, GIF, BMP, TIFF, WebP, ICO — validators and end-of-file walkers.

use super::Walk;
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::view::{Buffered, ByteView};
use memchr::memchr;
use strata_kernel::bytes::{u16_be, u16_le, u32_be, u32_le, u8_at};
use strata_kernel::{ByteRange, Confidence, Damage};

/// Largest chunk whose CRC we verify while walking (bigger ones are only skipped).
const CRC_LIMIT: u32 = 16 << 20;
const MAX_SEGMENTS: usize = 100_000;

/// Walk JPEG markers (including entropy-coded scans) until EOI.
pub fn jpeg_walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut r = Buffered::new(view);
    let mut pos = 2u64;
    while w.ok + w.bad < MAX_SEGMENTS {
        // Skip fill bytes.
        while r.byte(pos) == Some(0xFF) && r.byte(pos + 1) == Some(0xFF) {
            pos += 1;
        }
        let (Some(0xFF), Some(marker)) = (r.byte(pos), r.byte(pos + 1)) else {
            if pos < r.len() {
                w.bad += 1;
                w.damage.push(Damage::corrupt(ByteRange::new(pos, 2), "expected JPEG marker"));
            }
            break;
        };
        match marker {
            0xD9 => {
                w.ok += 1;
                w.end = Some(pos + 2);
                break;
            }
            0xD0..=0xD8 | 0x01 => {
                w.ok += 1;
                pos += 2;
                continue;
            }
            0x00 => {
                w.bad += 1;
                break;
            }
            _ => {}
        }
        let Some(len) = u16_be(r.slice(pos + 2, 2), 0).filter(|l| *l >= 2) else {
            w.bad += 1;
            break;
        };
        if matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            let sof = r.slice(pos + 4, 5).to_vec();
            if let (Some(h), Some(wd)) = (u16_be(&sof, 1), u16_be(&sof, 3)) {
                w.items.push((format!("dimensions={wd}x{h}"), 0));
            }
        }
        if marker == 0xE1 && r.slice(pos + 4, 4) == b"Exif" {
            w.items.push(("exif".into(), u64::from(len)));
        }
        w.ok += 1;
        pos += 2 + u64::from(len);
        if marker == 0xDA {
            pos = scan_entropy(&mut r, pos);
        }
    }
    w
}

/// Position of the first real marker after entropy-coded data starting at `pos`.
fn scan_entropy(r: &mut Buffered<'_>, mut pos: u64) -> u64 {
    loop {
        let chunk = r.slice(pos, 64 * 1024);
        if chunk.len() < 2 {
            return pos + chunk.len() as u64;
        }
        let mut i = 0;
        while let Some(j) = memchr(0xFF, &chunk[i..]) {
            let at = i + j;
            match chunk.get(at + 1) {
                Some(0x00 | 0xD0..=0xD7 | 0xFF) => i = at + 1,
                Some(_) => return pos + at as u64,
                None => break,
            }
        }
        pos += (chunk.len() - 1) as u64;
    }
}

pub fn jpeg(data: &[u8]) -> Option<Probe> {
    // The first segment after SOI is an APPn, table, frame, comment or restart interval.
    let first = *data.get(3)?;
    if !matches!(first, 0xE0..=0xEF | 0xDB | 0xC4 | 0xC0..=0xC3 | 0xFE | 0xDD) {
        return None;
    }
    let w = jpeg_walk(&data);
    if w.ok < 2 && data.len() > 64 {
        return None;
    }
    let mut p = Probe::certain(TypeId::Jpeg).with_len(w.end);
    let mut structure = ratio(w.ok, w.ok + w.bad);
    if w.end.is_none() {
        structure *= 0.8;
        p.damaged(Damage::truncated("no end-of-image marker"));
    }
    p = p.with_structure(structure);
    for (name, _) in &w.items {
        match name.split_once('=') {
            Some((k, v)) => p.property(k, v),
            None => p.note(name.clone()),
        }
    }
    p.damage.extend(w.damage);
    Some(p)
}

/// Walk PNG chunks until IEND, checking CRCs.
pub fn png_walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut pos = 8u64;
    while w.ok + w.bad < MAX_SEGMENTS {
        let head = view.bytes(pos, 8);
        let (Some(len), Some(kind)) = (u32_be(&head, 0), head.get(4..8)) else { break };
        if !kind.iter().all(u8::is_ascii_alphabetic) || len > 0x7FFF_FFFF {
            w.bad += 1;
            w.damage.push(Damage::corrupt(ByteRange::new(pos, 8), "invalid PNG chunk header"));
            break;
        }
        let total = 12 + u64::from(len);
        if len <= CRC_LIMIT {
            let body = view.bytes(pos + 4, 4 + len as usize + 4);
            let crc_ok = body.len() == 8 + len as usize
                && u32_be(&body, 4 + len as usize) == Some(crc32fast::hash(&body[..4 + len as usize]));
            if crc_ok {
                w.ok += 1;
            } else {
                w.bad += 1;
                w.damage.push(Damage::corrupt(ByteRange::new(pos, total), format!("PNG {} chunk CRC mismatch", String::from_utf8_lossy(kind))));
            }
            if kind == b"IHDR"
                && let (Some(wd), Some(h)) = (u32_be(&body, 4), u32_be(&body, 8))
            {
                w.items.push((format!("{wd}x{h}"), 0));
            }
        }
        pos += total;
        if kind == b"IEND" {
            w.end = Some(pos);
            break;
        }
    }
    w
}

pub fn png(data: &[u8]) -> Option<Probe> {
    let w = png_walk(&data);
    let mut p = Probe::certain(TypeId::Png).with_len(w.end).with_structure(ratio(w.ok, w.ok + w.bad));
    if w.end.is_none() {
        p.damaged(Damage::truncated("no IEND chunk"));
    }
    if let Some((dims, _)) = w.items.first() {
        p.property("dimensions", dims);
    }
    p.damage.extend(w.damage);
    Some(p)
}

/// Walk GIF blocks until the trailer.
pub fn gif_walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut r = Buffered::new(view);
    let packed = r.byte(10).unwrap_or(0);
    let mut pos = 13 + if packed & 0x80 != 0 { 3u64 << ((packed & 7) + 1) } else { 0 };
    while w.ok + w.bad < MAX_SEGMENTS {
        match r.byte(pos) {
            Some(0x3B) => {
                w.end = Some(pos + 1);
                break;
            }
            Some(0x2C) => {
                let lp = r.byte(pos + 9).unwrap_or(0);
                pos += 10 + if lp & 0x80 != 0 { 3u64 << ((lp & 7) + 1) } else { 0 } + 1;
            }
            Some(0x21) => pos += 2,
            Some(_) => {
                w.bad += 1;
                w.damage.push(Damage::corrupt(ByteRange::new(pos, 1), "invalid GIF block"));
                break;
            }
            None => break,
        }
        // Data sub-blocks.
        while let Some(n) = r.byte(pos) {
            pos += 1 + u64::from(n);
            if n == 0 {
                break;
            }
        }
        w.ok += 1;
    }
    w
}

pub fn gif(data: &[u8]) -> Option<Probe> {
    let w = gif_walk(&data);
    let mut p = Probe::certain(TypeId::Gif).with_len(w.end).with_structure(if w.end.is_some() { 1.0 } else { 0.6 });
    p.property("dimensions", format!("{}x{}", u16_le(data, 6)?, u16_le(data, 8)?));
    p.damage.extend(w.damage);
    Some(p)
}

pub fn bmp(data: &[u8]) -> Option<Probe> {
    let size = u32_le(data, 2)?;
    let pixels = u32_le(data, 10)?;
    let dib = u32_le(data, 14)?;
    let planes = u16_le(data, 26)?;
    let bpp = u16_le(data, 28)?;
    let ok = u32_le(data, 6)? == 0
        && matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124)
        && pixels >= 14 + dib
        && pixels < size
        && planes == 1
        && matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32);
    if !ok {
        return None;
    }
    let mut p = Probe::new(TypeId::Bmp, Confidence::new(0.9)).with_len(Some(u64::from(size)));
    p.property("dimensions", format!("{}x{}", u32_le(data, 18)?, (u32_le(data, 22)? as i32).unsigned_abs()));
    Some(p)
}

pub fn tiff(data: &[u8]) -> Option<Probe> {
    let le = data.starts_with(b"II");
    let r16 = |o| if le { u16_le(data, o) } else { u16_be(data, o) };
    let r32 = |o| if le { u32_le(data, o) } else { u32_be(data, o) };
    let ifd = r32(4)? as usize;
    if ifd < 8 {
        return None;
    }
    let mut p = Probe::new(TypeId::Tiff, Confidence::new(0.9));
    match r16(ifd) {
        Some(n) if (1..=500).contains(&n) => {
            let valid = (0..usize::from(n)).filter(|i| r16(ifd + 2 + i * 12 + 2).is_some_and(|t| (1..=13).contains(&t))).count();
            p = p.with_structure(ratio(valid, usize::from(n)));
            p.property("ifd_entries", n);
        }
        Some(_) => return None,
        None => {
            p = p.with_structure(0.3);
            p.damaged(Damage::missing(None, "first IFD outside available data"));
        }
    }
    Some(p)
}

pub fn webp(data: &[u8]) -> Option<Probe> {
    if !data.starts_with(b"RIFF") {
        return None;
    }
    let chunk = data.get(12..16)?;
    if !matches!(chunk, b"VP8 " | b"VP8L" | b"VP8X") {
        return None;
    }
    let mut p = Probe::certain(TypeId::Webp).with_len(Some(u64::from(u32_le(data, 4)?) + 8));
    p.property("codec", String::from_utf8_lossy(chunk).trim());
    Some(p)
}

pub fn ico(data: &[u8]) -> Option<Probe> {
    let count = usize::from(u16_le(data, 4)?);
    if count == 0 || count > 256 {
        return None;
    }
    let mut end = 0u64;
    for i in 0..count {
        let e = 6 + i * 16;
        let (Some(reserved), Some(size), Some(off)) = (u8_at(data, e + 3), u32_le(data, e + 8), u32_le(data, e + 12)) else {
            return None;
        };
        if reserved != 0 || size == 0 || (off as usize) < 6 + count * 16 {
            return None;
        }
        end = end.max(u64::from(off) + u64::from(size));
    }
    let mut p = Probe::new(TypeId::Ico, Confidence::new(0.85)).with_len(Some(end));
    p.property("images", count);
    Some(p)
}
