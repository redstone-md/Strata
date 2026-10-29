//! POSIX ustar walker.

use super::Walk;
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use crate::view::ByteView;
use strata_kernel::{ByteRange, Damage};

const MAX_MEMBERS: usize = 1_000_000;

fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        // GNU base-256 encoding.
        return Some(field[1..].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)));
    }
    let s = std::str::from_utf8(field).ok()?;
    let s = s.trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() { Some(0) } else { u64::from_str_radix(s, 8).ok() }
}

fn checksum_ok(h: &[u8]) -> bool {
    let Some(stored) = h.get(148..156).and_then(octal) else { return false };
    let sum: u64 = h.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u64::from(*b) }).sum();
    sum == stored
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Walk tar headers from offset 0.
pub fn walk(view: &dyn ByteView) -> Walk {
    let mut w = Walk::default();
    let mut pos = 0u64;
    let mut long_name: Option<String> = None;
    while w.items.len() < MAX_MEMBERS {
        let h = view.bytes(pos, 512);
        if h.len() < 512 {
            w.damage.push(Damage::truncated("tar ends inside a header"));
            break;
        }
        if h.iter().all(|b| *b == 0) {
            w.end = Some(pos + 1024);
            break;
        }
        if !checksum_ok(&h) {
            w.bad += 1;
            w.damage.push(Damage::corrupt(ByteRange::new(pos, 512), "tar header checksum mismatch"));
            break;
        }
        w.ok += 1;
        let size = octal(&h[124..136]).unwrap_or(0);
        let kind = h[156];
        let data_pos = pos + 512;
        if kind == b'L' {
            long_name = Some(cstr(&view.bytes(data_pos, size.min(4096) as usize)));
        } else if kind != b'x' && kind != b'g' {
            let mut name = cstr(&h[0..100]);
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
            w.items.push((long_name.take().unwrap_or(name), size));
        }
        pos = data_pos + size.div_ceil(512) * 512;
    }
    if w.end.is_none() && w.ok > 0 && pos >= view.view_len() {
        w.end = Some(pos.min(view.view_len()));
    }
    w
}

pub fn tar(data: &[u8]) -> Option<Probe> {
    let w = walk(&data);
    if w.ok == 0 {
        return None;
    }
    let mut p = Probe::certain(TypeId::Tar).with_len(w.end).with_structure(ratio(w.ok, w.ok + w.bad));
    for (name, size) in w.items.iter().take(2000) {
        p.item(InnerKind::Member, name.clone(), Some(*size));
    }
    p.damage.extend(w.damage);
    Some(p)
}
