//! Compressed archives and containers: 7z, CAB, GZIP, BZIP2, XZ, ISO 9660 (RAR and TAR have
//! their own walkers).

use super::Walk;
use super::deflate::measure_deflate;
use crate::probe::Probe;
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use crate::view::ByteView;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};
use strata_kernel::{ByteRange, Confidence, Damage};

pub use super::rar::{rar4, rar5};
pub use super::tar::tar;

pub fn seven_zip(data: &[u8]) -> Option<Probe> {
    let header = data.get(12..32)?;
    if u8_at(data, 6)? != 0 {
        return None;
    }
    let mut p = Probe::certain(TypeId::SevenZip);
    let next_off = u64_le(data, 12)?;
    let next_size = u64_le(data, 20)?;
    if crc32fast::hash(header) == u32_le(data, 8)? {
        p = p.with_len(32u64.checked_add(next_off)?.checked_add(next_size));
    } else {
        p.damaged(Damage::corrupt(ByteRange::new(8, 24), "start header CRC mismatch"));
        p = p.with_structure(0.5);
    }
    p.property("version", format!("0.{}", u8_at(data, 7)?));
    Some(p)
}

pub fn cab(data: &[u8]) -> Option<Probe> {
    let size = u32_le(data, 8)?;
    let files_off = u32_le(data, 16)? as usize;
    let (minor, major) = (u8_at(data, 24)?, u8_at(data, 25)?);
    if major != 1 || minor != 3 || size < 36 {
        return None;
    }
    let mut p = Probe::certain(TypeId::Cab).with_len(Some(u64::from(size)));
    let count = u16_le(data, 28)?;
    let mut pos = files_off;
    let mut listed = 0;
    for _ in 0..count {
        let Some(len) = u32_le(data, pos) else { break };
        let name_start = pos + 16;
        let Some(name_len) = data.get(name_start..).and_then(|r| memchr::memchr(0, &r[..r.len().min(512)])) else {
            break;
        };
        let name = String::from_utf8_lossy(&data[name_start..name_start + name_len]).into_owned();
        p.item(InnerKind::Member, name, Some(u64::from(len)));
        listed += 1;
        pos = name_start + name_len + 1;
    }
    p = p.with_structure(if count == 0 { 1.0 } else { listed as f32 / f32::from(count) });
    p.property("files", count);
    Some(p)
}

/// Header length of one GZIP member at `pos`, plus the original file name when stored.
fn gzip_header(view: &dyn ByteView, pos: u64) -> Option<(u64, Option<String>)> {
    let h = view.bytes(pos, 10);
    if h.get(..3)? != b"\x1F\x8B\x08" || h.get(3)? & 0xE0 != 0 {
        return None;
    }
    let flags = h[3];
    let mut at = pos + 10;
    if flags & 0x04 != 0 {
        at += 2 + u64::from(u16_le(&view.bytes(at, 2), 0)?);
    }
    let mut name = None;
    for bit in [0x08u8, 0x10] {
        if flags & bit != 0 {
            let tail = view.bytes(at, 1024);
            let end = memchr::memchr(0, &tail)?;
            if bit == 0x08 {
                name = Some(String::from_utf8_lossy(&tail[..end]).into_owned());
            }
            at += end as u64 + 1;
        }
    }
    if flags & 0x02 != 0 {
        at += 2;
    }
    Some((at - pos, name))
}

/// Walk concatenated GZIP members starting at `start`.
pub fn gzip_walk(view: &dyn ByteView, start: u64) -> Walk {
    let mut walk = Walk::default();
    let mut pos = start;
    while let Some((hlen, name)) = gzip_header(view, pos) {
        let run = measure_deflate(view, pos + hlen);
        walk.items.push((name.unwrap_or_default(), run.produced));
        if !run.complete {
            walk.bad += 1;
            walk.damage.push(if run.invalid {
                Damage::corrupt(ByteRange::new(pos + hlen + run.consumed, 1), format!("gzip member at {pos:#x}: invalid deflate data"))
            } else {
                Damage::truncated(format!("gzip member at {pos:#x}: deflate stream incomplete"))
            });
            walk.invalid_start |= walk.ok == 0 && run.invalid && run.consumed < 64;
            break;
        }
        walk.ok += 1;
        pos += hlen + run.consumed + 8;
        walk.end = Some(pos);
        if walk.items.len() >= 10_000 {
            break;
        }
    }
    walk
}

pub fn gzip(data: &[u8]) -> Option<Probe> {
    gzip_header(&data, 0)?;
    let walk = gzip_walk(&data, 0);
    // A first member whose deflate data is garbage from the start is not a GZIP stream.
    if walk.invalid_start {
        return None;
    }
    let mut p = Probe::new(TypeId::Gzip, Confidence::new(if walk.ok > 0 { 0.95 } else { 0.8 }));
    for (name, size) in walk.items.iter().filter(|(n, _)| !n.is_empty()) {
        p.item(InnerKind::Member, name.clone(), Some(*size));
    }
    if walk.items.len() > 1 {
        p.property("members", walk.items.len());
    }
    p = p.with_structure(if walk.ok > 0 { 1.0 } else { 0.5 }).with_len(walk.end);
    p.damage.extend(walk.damage);
    Some(p)
}

pub fn bzip2(data: &[u8]) -> Option<Probe> {
    let level = u8_at(data, 3)?;
    let block = data.get(4..10)?;
    if !(b'1'..=b'9').contains(&level) || (block != b"\x31\x41\x59\x26\x53\x59" && block != b"\x17\x72\x45\x38\x50\x90") {
        return None;
    }
    let mut p = Probe::new(TypeId::Bzip2, Confidence::new(0.9));
    p.property("block_size_kb", u32::from(level - b'0') * 100);
    Some(p)
}

pub fn xz(data: &[u8]) -> Option<Probe> {
    let flags = data.get(6..8)?;
    if flags[0] != 0 || flags[1] > 0x0F {
        return None;
    }
    let mut p = Probe::certain(TypeId::Xz);
    if crc32fast::hash(flags) != u32_le(data, 8)? {
        p.damaged(Damage::corrupt(ByteRange::new(6, 6), "stream header CRC mismatch"));
        p = p.with_structure(0.5);
    }
    Some(p.with_len(xz_end(&data, data.len() as u64)))
}

/// End of the XZ stream starting at offset 0 of `view`, found via its CRC-checked footer.
pub fn xz_end(view: &dyn ByteView, cap: u64) -> Option<u64> {
    let flags = view.bytes(6, 2);
    let mut from = 12;
    while let Some(at) = view.find(b"YZ", from, cap) {
        from = at + 1;
        let Some(footer) = at.checked_sub(10) else { continue };
        let f = view.bytes(footer, 12);
        if (at + 2) % 4 == 0 && f.get(8..10) == Some(flags.as_slice()) && u32_le(&f, 0) == Some(crc32fast::hash(&f[4..10])) {
            return Some(at + 2);
        }
    }
    None
}

pub fn iso(data: &[u8]) -> Option<Probe> {
    let descriptors = (0..16).map(|k| 0x8000 + k * 0x800).filter_map(|d| data.get(d..d + 0x800));
    let mut seen = false;
    for pvd in descriptors {
        if pvd.get(1..6) != Some(b"CD001".as_slice()) {
            break;
        }
        seen = true;
        if pvd[0] != 1 {
            continue;
        }
        let blocks = u32_le(pvd, 0x50)?;
        let block_size = u16_le(pvd, 0x80)?;
        let mut p = Probe::certain(TypeId::Iso9660).with_len(Some(u64::from(blocks) * u64::from(block_size)));
        let label = String::from_utf8_lossy(pvd.get(0x28..0x48)?).trim().to_string();
        if !label.is_empty() {
            p.property("volume", label);
        }
        return Some(p);
    }
    seen.then(|| {
        let mut p = Probe::new(TypeId::Iso9660, Confidence::new(0.8)).with_structure(0.5);
        p.note("primary volume descriptor not found");
        p
    })
}
