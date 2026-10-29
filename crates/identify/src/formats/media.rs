//! Audio/video containers: MP3, RIFF (WAV/AVI), ISO BMFF (MP4/MOV), Matroska, FLV.

use super::Walk;
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::view::ByteView;
use strata_kernel::bytes::{u32_be, u32_le, u64_be, u8_at};
use strata_kernel::{Confidence, Damage};

const MPEG1_L3_KBPS: [u32; 15] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
const MPEG2_L3_KBPS: [u32; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];

/// Length of the MPEG audio layer III frame at `pos`, if its header is valid.
fn mp3_frame(data: &[u8], pos: usize) -> Option<usize> {
    let h = data.get(pos..pos + 4)?;
    if h[0] != 0xFF || !matches!(h[1], 0xFA | 0xFB | 0xF2 | 0xF3) {
        return None;
    }
    let mpeg1 = h[1] & 0x08 != 0;
    let idx = usize::from(h[2] >> 4);
    let sr_idx = usize::from((h[2] >> 2) & 3);
    if idx == 0 || idx == 15 || sr_idx == 3 {
        return None;
    }
    let pad = usize::from((h[2] >> 1) & 1);
    let (kbps, rates, factor) = if mpeg1 {
        (MPEG1_L3_KBPS[idx], [44100, 48000, 32000], 144)
    } else {
        (MPEG2_L3_KBPS[idx], [22050, 24000, 16000], 72)
    };
    Some(factor * kbps as usize * 1000 / rates[sr_idx] + pad)
}

fn consecutive_frames(data: &[u8], mut pos: usize, want: usize) -> usize {
    let mut n = 0;
    while n < want {
        match mp3_frame(data, pos) {
            Some(len) if len > 4 => {
                pos += len;
                n += 1;
            }
            _ => break,
        }
    }
    n
}

pub fn mp3(data: &[u8]) -> Option<Probe> {
    if data.starts_with(b"ID3") {
        let v = u8_at(data, 3)?;
        let size = data.get(6..10)?;
        if !(2..=4).contains(&v) || size.iter().any(|b| b & 0x80 != 0) {
            return None;
        }
        let tag = 10 + size.iter().fold(0usize, |acc, b| (acc << 7) | usize::from(*b));
        let mut p = Probe::certain(TypeId::Mp3);
        p.property("id3", format!("2.{v}"));
        let frames = consecutive_frames(data, tag, 3);
        if data.len() > tag + 4 {
            p = p.with_structure(if frames > 0 { 1.0 } else { 0.5 });
        }
        return Some(p);
    }
    (consecutive_frames(data, 0, 4) >= 3).then(|| Probe::new(TypeId::Mp3, Confidence::new(0.8)))
}

pub fn riff(data: &[u8]) -> Option<Probe> {
    if !data.starts_with(b"RIFF") {
        return None;
    }
    let id = match data.get(8..12)? {
        b"WAVE" => TypeId::Wav,
        b"AVI " => TypeId::Avi,
        _ => return None,
    };
    let size = u64::from(u32_le(data, 4)?);
    let mut p = Probe::certain(id).with_len(Some(size + 8 + (size & 1)));
    let (mut ok, mut bad, mut pos) = (0, 0, 12usize);
    while let (Some(fourcc), Some(len)) = (data.get(pos..pos + 4), u32_le(data, pos + 4)) {
        if !fourcc.iter().all(|b| (0x20..0x7F).contains(b)) {
            bad += 1;
            break;
        }
        ok += 1;
        p.item(crate::InnerKind::Object, String::from_utf8_lossy(fourcc).into_owned(), Some(u64::from(len)));
        pos += 8 + len as usize + (len as usize & 1);
        if ok > 1000 {
            break;
        }
    }
    Some(p.with_structure(if ok + bad == 0 { 0.5 } else { ratio(ok, ok + bad) }))
}

const MP4_TOP: &[&[u8; 4]] = &[
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pdin", b"moof", b"mfra",
    b"styp", b"sidx", b"pnot", b"junk", b"PICT", b"prfl", b"emsg", b"prft", b"ssix", b"jP  ",
];

/// Walk top-level ISO BMFF boxes; the end is where the box chain stops being valid.
pub fn mp4_walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut pos = 0u64;
    let len = view.view_len();
    while pos < len && w.ok < 100_000 {
        let h = view.bytes(pos, 16);
        let (Some(size32), Some(kind)) = (u32_be(&h, 0), h.get(4..8)) else { break };
        if !MP4_TOP.iter().any(|k| k.as_slice() == kind) {
            break;
        }
        let size = match size32 {
            0 => len - pos,
            1 => match u64_be(&h, 8) {
                Some(s) if s >= 16 => s,
                _ => break,
            },
            s if s >= 8 => u64::from(s),
            _ => break,
        };
        w.ok += 1;
        w.items.push((String::from_utf8_lossy(kind).into_owned(), size));
        pos = pos.saturating_add(size);
        w.end = Some(pos);
    }
    w
}

pub fn mp4(data: &[u8]) -> Option<Probe> {
    let w = mp4_walk(&data);
    let first = w.items.first().map(|(k, _)| k.as_str());
    let plausible = match first {
        Some("ftyp") => true,
        Some("moov") => matches!(data.get(12..16), Some(b"mvhd" | b"cmov" | b"prfl")),
        _ => w.ok >= 2,
    };
    if !plausible {
        return None;
    }
    let brand = (data.get(4..8) == Some(b"ftyp")).then(|| data.get(8..12)).flatten();
    let id = match brand {
        Some(b"qt  ") | None => TypeId::Mov,
        Some(_) => TypeId::Mp4,
    };
    let has = |k: &str| w.items.iter().any(|(n, _)| n == k);
    let mut p = Probe::certain(id).with_structure(if has("moov") || has("moof") { 1.0 } else { 0.6 });
    if let Some(b) = brand {
        p.property("brand", String::from_utf8_lossy(b).trim());
    }
    // Only trust the end when it lands inside the buffer we were given.
    p = p.with_len(w.end.filter(|e| *e <= data.len() as u64));
    for (name, size) in w.items.iter().take(64) {
        p.item(crate::InnerKind::Object, name.clone(), Some(*size));
    }
    if !has("moov") && !has("moof") {
        p.damaged(Damage::missing(None, "no moov box in available data (index lost or later in file)"));
    }
    Some(p)
}

/// EBML variable-length integer: (value, encoded length). All-ones value means "unknown".
pub fn ebml_vint(data: &[u8], pos: usize, keep_marker: bool) -> Option<(u64, usize)> {
    let first = *data.get(pos)?;
    let len = first.leading_zeros() as usize + 1;
    if len > 8 {
        return None;
    }
    let bytes = data.get(pos..pos + len)?;
    let mut v = if keep_marker { u64::from(first) } else { u64::from(first) & (0xFF >> len) };
    for b in &bytes[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

pub fn mkv(data: &[u8]) -> Option<Probe> {
    let (_, id_len) = ebml_vint(data, 0, true)?;
    let (head_size, size_len) = ebml_vint(data, id_len, false)?;
    let body = id_len + size_len;
    let seg = body.checked_add(usize::try_from(head_size).ok()?)?;
    let header = data.get(body..seg)?;
    let doc = memchr::memmem::find(header, b"\x42\x82")
        .and_then(|p| {
            let (n, l) = ebml_vint(header, p + 2, false)?;
            let start = p + 2 + l;
            header.get(start..start.checked_add(usize::try_from(n).ok()?)?)
        })
        .map(|d| String::from_utf8_lossy(d).into_owned())?;
    if doc != "matroska" && doc != "webm" {
        return None;
    }
    let mut p = Probe::certain(TypeId::Mkv);
    p.property("doctype", &doc);
    if data.get(seg..seg + 4) == Some(b"\x18\x53\x80\x67")
        && let Some((size, l)) = ebml_vint(data, seg + 4, false)
        && size != (1u64 << (7 * l)) - 1
    {
        p = p.with_len(Some((seg + 4 + l) as u64 + size));
    }
    Some(p)
}

/// Walk FLV tags until they stop validating.
pub fn flv_walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let header = view.bytes(0, 9);
    let mut pos = u64::from(u32_be(&header, 5).unwrap_or(9)) + 4;
    w.end = Some(pos);
    while w.ok < 10_000_000 {
        let t = view.bytes(pos, 11);
        let (Some(kind), Some(size)) = (t.first(), u32_be(&t, 0).map(|v| v & 0x00FF_FFFF)) else { break };
        if !matches!(kind & 0x1F, 8 | 9 | 18) || t.get(8..11) != Some(&[0, 0, 0]) {
            break;
        }
        let next = pos + 11 + u64::from(size);
        if u32_be(&view.bytes(next, 4), 0) != Some(size + 11) {
            break;
        }
        w.ok += 1;
        pos = next + 4;
        w.end = Some(pos);
    }
    w
}

pub fn flv(data: &[u8]) -> Option<Probe> {
    if u32_be(data, 5)? < 9 || u8_at(data, 4)? & 0xFA != 0 {
        return None;
    }
    let w = flv_walk(&data);
    let mut p = Probe::certain(TypeId::Flv).with_structure(if w.ok > 0 { 1.0 } else { 0.5 });
    p.property("tags", w.ok);
    Some(p)
}
