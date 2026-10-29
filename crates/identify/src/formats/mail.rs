//! Mail stores: Outlook PST/OST, Outlook Express DBX, Unix mbox.

use crate::probe::Probe;
use crate::registry::TypeId;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};

pub fn pst(data: &[u8]) -> Option<Probe> {
    let client = data.get(8..10)?;
    let version = u16_le(data, 10)?;
    let ost = match client {
        b"SM" => false,
        b"SO" => true,
        _ => return None,
    };
    let (len, crypt, flavour) = match version {
        14 | 15 => (u32_le(data, 0xA8).map(u64::from), u8_at(data, 0x1CD), "ansi"),
        v if v >= 23 => (u64_le(data, 0xB8), u8_at(data, 0x201), "unicode"),
        _ => return None,
    };
    let mut p = Probe::certain(TypeId::Pst).with_len(len);
    p.property("store", if ost { "ost" } else { "pst" });
    p.property("format", flavour);
    match crypt {
        Some(1) => p.note("permutation-encoded (compressible encryption)"),
        Some(2) => p.note("cyclic-encoded (high encryption)"),
        _ => {}
    }
    Some(p)
}

pub fn dbx(data: &[u8]) -> Option<Probe> {
    let kind = match data.get(4..8)? {
        [0xC5, 0xFD, 0x74, 0x6F] => "messages",
        [0xC6, 0xFD, 0x74, 0x6F] => "folders",
        _ => return None,
    };
    let mut p = Probe::certain(TypeId::Dbx);
    p.property("kind", kind);
    if let Some(count) = u32_le(data, 0xC4) {
        p.property("items", count);
    }
    Some(p)
}

pub fn mbox(data: &[u8]) -> Option<Probe> {
    crate::text::validate(data).filter(|p| p.id == TypeId::Mbox)
}
