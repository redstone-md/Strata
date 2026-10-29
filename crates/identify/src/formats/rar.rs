//! RAR 4 and RAR 5 block walkers (member names, archive end, header CRC checks).

use super::Walk;
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use crate::view::ByteView;
use strata_kernel::bytes::{u16_le, u32_le, u8_at};
use strata_kernel::{ByteRange, Damage};

const MAX_BLOCKS: usize = 200_000;

/// Walk RAR 4 blocks after the 7-byte marker.
pub fn walk4(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut pos = 7u64;
    for _ in 0..MAX_BLOCKS {
        let head = view.bytes(pos, 11);
        let (Some(crc), Some(kind), Some(flags), Some(size)) =
            (u16_le(&head, 0), u8_at(&head, 2), u16_le(&head, 3), u16_le(&head, 5))
        else {
            break;
        };
        if !(0x72..=0x7B).contains(&kind) || size < 7 {
            w.damage.push(Damage::corrupt(ByteRange::new(pos, 7), "invalid RAR block header"));
            w.bad += 1;
            break;
        }
        let header = view.bytes(pos, usize::from(size));
        let crc_ok = header.len() == usize::from(size) && (crc32fast::hash(&header[2..]) & 0xFFFF) as u16 == crc;
        if crc_ok {
            w.ok += 1;
        } else {
            w.bad += 1;
            w.damage.push(Damage::corrupt(ByteRange::new(pos, u64::from(size)), "RAR block header CRC mismatch"));
        }
        let mut add = if flags & 0x8000 != 0 || kind == 0x74 { u64::from(u32_le(&header, 7).unwrap_or(0)) } else { 0 };
        if kind == 0x73 && flags & 0x0080 != 0 {
            w.notes.push("headers are encrypted".into());
        }
        if kind == 0x74 {
            let large = flags & 0x0100 != 0;
            if large {
                add |= u64::from(u32_le(&header, 32).unwrap_or(0)) << 32;
            }
            let name_len = usize::from(u16_le(&header, 26).unwrap_or(0));
            let name_at = if large { 40 } else { 32 };
            let raw = header.get(name_at..name_at + name_len).unwrap_or_default();
            let name = raw.split(|b| *b == 0).next().unwrap_or_default();
            let unpacked = u64::from(u32_le(&header, 11).unwrap_or(0));
            w.items.push((String::from_utf8_lossy(name).into_owned(), unpacked));
            if flags & 0x0004 != 0 {
                w.encrypted += 1;
            }
        }
        pos += u64::from(size) + add;
        if kind == 0x7B {
            w.end = Some(pos);
            break;
        }
        if pos >= view.view_len() {
            break;
        }
    }
    w
}

/// RAR 5 variable-length integer.
fn vint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let b = *data.get(*pos)?;
        *pos += 1;
        value |= u64::from(b & 0x7F).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Walk RAR 5 blocks after the 8-byte marker.
pub fn walk5(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut pos = 8u64;
    for _ in 0..MAX_BLOCKS {
        let head = view.bytes(pos, 16);
        let mut at = 4;
        let Some(size) = vint(&head, &mut at).filter(|s| *s > 0 && *s < 2 << 20) else { break };
        let header = view.bytes(pos, at + size as usize);
        if header.len() < at + size as usize {
            w.damage.push(Damage::truncated("RAR5 header truncated"));
            break;
        }
        let crc_ok = u32_le(&header, 0) == Some(crc32fast::hash(&header[4..]));
        let mut p = at;
        let kind = vint(&header, &mut p).unwrap_or(0);
        let flags = vint(&header, &mut p).unwrap_or(0);
        if flags & 1 != 0 {
            vint(&header, &mut p);
        }
        let data_size = if flags & 2 != 0 { vint(&header, &mut p).unwrap_or(0) } else { 0 };
        if !crc_ok || !(1..=5).contains(&kind) {
            w.bad += 1;
            w.damage.push(Damage::corrupt(ByteRange::new(pos, header.len() as u64), "RAR5 block header invalid"));
            break;
        }
        w.ok += 1;
        if kind == 4 {
            w.notes.push("headers are encrypted".into());
            break;
        }
        if kind == 2 {
            let fflags = vint(&header, &mut p).unwrap_or(0);
            let unpacked = vint(&header, &mut p).unwrap_or(0);
            vint(&header, &mut p);
            p += 4 * (usize::from(fflags & 2 != 0) + usize::from(fflags & 4 != 0));
            vint(&header, &mut p);
            vint(&header, &mut p);
            let name_len = vint(&header, &mut p).unwrap_or(0) as usize;
            let name = header.get(p..p + name_len).unwrap_or_default();
            w.items.push((String::from_utf8_lossy(name).into_owned(), unpacked));
        }
        pos += header.len() as u64 + data_size;
        if kind == 5 {
            w.end = Some(pos);
            break;
        }
        if pos >= view.view_len() {
            break;
        }
    }
    w
}

fn probe(id: TypeId, w: Walk) -> Option<Probe> {
    let mut p = Probe::certain(id).with_len(w.end).with_structure(ratio(w.ok, w.ok + w.bad));
    if w.ok == 0 {
        // The 7/8-byte marker alone is still strong evidence.
        p = p.with_confidence(strata_kernel::Confidence::new(0.8));
        p.note("no intact block header after the marker");
    }
    for (name, size) in w.items.iter().take(2000) {
        p.item(InnerKind::Member, name.clone(), Some(*size));
    }
    if w.encrypted > 0 {
        p.note(format!("{} encrypted member(s)", w.encrypted));
    }
    p.notes.extend(w.notes);
    p.damage.extend(w.damage);
    Some(p)
}

pub fn rar4(data: &[u8]) -> Option<Probe> {
    probe(TypeId::Rar4, walk4(&data))
}

pub fn rar5(data: &[u8]) -> Option<Probe> {
    probe(TypeId::Rar5, walk5(&data))
}
