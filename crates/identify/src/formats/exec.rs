//! Executables: PE (EXE/DLL/SYS) and ELF.

use crate::probe::Probe;
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use strata_kernel::bytes::{u16_be, u16_le, u32_be, u32_le, u64_be, u64_le, u8_at};
use strata_kernel::{Confidence, Damage};

const KNOWN_MACHINES: &[(u16, &str)] = &[
    (0x14C, "x86"),
    (0x8664, "x64"),
    (0x1C0, "arm"),
    (0x1C4, "armnt"),
    (0xAA64, "arm64"),
    (0x200, "ia64"),
    (0xEBC, "efi-bytecode"),
];

/// Parsed COFF + optional header facts.
pub struct PeImage {
    pub machine: &'static str,
    pub kind: TypeId,
    pub sections: Vec<(String, u64, u64)>,
    pub declared_len: Option<u64>,
    pub timestamp: u32,
}

impl PeImage {
    /// Parse the PE header at `pe` (position of `PE\0\0`) inside `data`.
    pub fn at(data: &[u8], pe: usize) -> Option<Self> {
        if data.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let machine_id = u16_le(data, pe + 4)?;
        let machine = KNOWN_MACHINES.iter().find(|(m, _)| *m == machine_id)?.1;
        let nsections = usize::from(u16_le(data, pe + 6)?);
        let opt_size = usize::from(u16_le(data, pe + 20)?);
        let characteristics = u16_le(data, pe + 22)?;
        let opt = pe + 24;
        let magic = u16_le(data, opt)?;
        if nsections == 0 || nsections > 96 || !matches!(magic, 0x10B | 0x20B) {
            return None;
        }
        let subsystem = u16_le(data, opt + 68)?;
        let dirs = opt + if magic == 0x20B { 112 } else { 96 };
        let kind = if characteristics & 0x2000 != 0 {
            TypeId::Dll
        } else if subsystem == 1 {
            TypeId::Sys
        } else {
            TypeId::Exe
        };
        let mut end = 0u64;
        let mut sections = Vec::new();
        let table = opt + opt_size;
        for i in 0..nsections {
            let s = table + i * 40;
            let Some(raw) = data.get(s..s + 8) else { break };
            let name = String::from_utf8_lossy(raw.split(|b| *b == 0).next().unwrap_or_default()).into_owned();
            let size = u64::from(u32_le(data, s + 16).unwrap_or(0));
            let ptr = u64::from(u32_le(data, s + 20).unwrap_or(0));
            end = end.max(ptr + size);
            sections.push((name, ptr, size));
        }
        // Authenticode certificate table sits after the sections (file offset, not RVA).
        if let (Some(cert_off), Some(cert_len)) = (u32_le(data, dirs + 4 * 8), u32_le(data, dirs + 4 * 8 + 4))
            && cert_off > 0
            && cert_len > 0
        {
            end = end.max(u64::from(cert_off) + u64::from(cert_len));
        }
        Some(Self { machine, kind, sections, declared_len: (end > 0).then_some(end), timestamp: u32_le(data, pe + 8)? })
    }

    pub fn into_probe(self, confidence: Confidence) -> Probe {
        let mut p = Probe::new(self.kind, confidence).with_len(self.declared_len);
        p.property("machine", self.machine);
        p.property("timestamp", self.timestamp);
        for (name, _, size) in &self.sections {
            p.item(InnerKind::Section, name.clone(), Some(*size));
        }
        p
    }
}

pub fn pe(data: &[u8]) -> Option<Probe> {
    let lfanew = u32_le(data, 0x3C)? as usize;
    if !(0x40..=0x1000).contains(&lfanew) {
        return None;
    }
    match PeImage::at(data, lfanew) {
        Some(img) => Some(img.into_probe(Confidence::new(0.95))),
        None if data.get(lfanew..lfanew + 4) == Some(b"PE\0\0") => {
            let mut p = Probe::new(TypeId::Pe, Confidence::new(0.7)).with_structure(0.3);
            p.damaged(Damage::corrupt(strata_kernel::ByteRange::new(lfanew as u64, 248), "PE header corrupt"));
            Some(p)
        }
        None => None,
    }
}

pub fn elf(data: &[u8]) -> Option<Probe> {
    let class = u8_at(data, 4)?;
    let endian = u8_at(data, 5)?;
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || u8_at(data, 6)? != 1 {
        return None;
    }
    let le = endian == 1;
    let r16 = |o| if le { u16_le(data, o) } else { u16_be(data, o) };
    let r32 = |o| if le { u32_le(data, o) } else { u32_be(data, o) };
    let r64 = |o| if le { u64_le(data, o) } else { u64_be(data, o) };
    let kind = r16(16)?;
    let (shoff, shent, shnum) = if class == 1 {
        (u64::from(r32(32)?), r16(46)?, r16(48)?)
    } else {
        (r64(40)?, r16(58)?, r16(60)?)
    };
    if kind > 4 {
        return None;
    }
    let mut p = Probe::certain(TypeId::Elf);
    if shoff > 0 && shnum > 0 {
        p = p.with_len(shoff.checked_add(u64::from(shent) * u64::from(shnum)));
    }
    p.property("class", if class == 1 { "elf32" } else { "elf64" });
    p.property("type", ["none", "rel", "exec", "dyn", "core"][usize::from(kind)]);
    p.property("machine", r16(18)?);
    Some(p)
}
