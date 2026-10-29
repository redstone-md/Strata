//! Windows system artefacts: registry hives, event logs, shortcuts, prefetch, MFT records,
//! IE index.dat.

use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use memchr::memmem;
use strata_kernel::bytes::{u16_le, u32_le, utf16le};
use strata_kernel::{ByteRange, Confidence, Damage};

pub fn regf(data: &[u8]) -> Option<Probe> {
    let major = u32_le(data, 20)?;
    let minor = u32_le(data, 24)?;
    if major != 1 || minor > 6 {
        return None;
    }
    let bins = u32_le(data, 40)?;
    let mut p = Probe::certain(TypeId::RegistryHive).with_len(Some(4096 + u64::from(bins)));
    let name = utf16le(data.get(48..112)?);
    if !name.is_empty() {
        p.property("hive_name", name.trim());
    }
    if let Some(header) = data.get(..508) {
        let xor = header.as_chunks::<4>().0.iter().fold(0u32, |acc, c| acc ^ u32::from_le_bytes(*c));
        if Some(xor) != u32_le(data, 508) {
            p.damaged(Damage::corrupt(ByteRange::new(0, 512), "base block checksum mismatch"));
            p = p.with_structure(0.8);
        }
    }
    if u32_le(data, 4) != u32_le(data, 8) {
        p.note("hive is dirty (sequence numbers differ): transaction logs may hold newer data");
    }
    let hbins = memmem::find_iter(data.get(4096..).unwrap_or_default(), b"hbin").filter(|p| p % 4096 == 0).count();
    if data.len() > 4096 {
        p.property("hbins_present", hbins);
        if hbins == 0 {
            p = p.with_structure(0.3);
        }
    }
    Some(p)
}

pub fn evt(data: &[u8]) -> Option<Probe> {
    if u32_le(data, 0)? != 0x30 || u32_le(data, 8)? != 1 || u32_le(data, 12)? != 1 {
        return None;
    }
    let mut p = Probe::certain(TypeId::Evt).with_len(u32_le(data, 32).map(u64::from));
    p.item(InnerKind::Object, format!("{} records", memmem::find_iter(data, b"LfLe").count().saturating_sub(1)), None);
    Some(p)
}

pub fn evtx(data: &[u8]) -> Option<Probe> {
    if u32_le(data, 32)? != 128 || u16_le(data, 38)? != 3 {
        return None;
    }
    let chunks = u16_le(data, 42)?;
    let mut p = Probe::certain(TypeId::Evtx).with_len(Some(4096 + u64::from(chunks) * 65536));
    if crc32fast::hash(data.get(..120)?) != u32_le(data, 124)? {
        p.damaged(Damage::corrupt(ByteRange::new(0, 128), "file header checksum mismatch"));
        p = p.with_structure(0.8);
    }
    let present = (0..usize::from(chunks)).filter(|i| data.get(4096 + i * 65536..4104 + i * 65536) == Some(b"ElfChnk\0")).count();
    let available = (0..usize::from(chunks)).filter(|i| data.len() >= 4104 + i * 65536).count();
    if available > 0 {
        p = p.with_structure(ratio(present, available));
    }
    p.property("chunks", chunks);
    Some(p)
}

pub fn lnk(data: &[u8]) -> Option<Probe> {
    let flags = u32_le(data, 0x14)?;
    let mut pos = 0x4Cusize;
    if flags & 0x01 != 0 {
        pos += 2 + usize::from(u16_le(data, pos)?);
    }
    let mut p = Probe::certain(TypeId::Lnk);
    if flags & 0x02 != 0 {
        let info = pos;
        pos += u32_le(data, pos)? as usize;
        if let Some(base) = u32_le(data, info + 16).filter(|o| *o > 0) {
            let s = data.get(info + base as usize..).unwrap_or_default();
            let end = s.iter().position(|b| *b == 0).unwrap_or(0);
            if end > 0 {
                p.property("target", String::from_utf8_lossy(&s[..end]));
            }
        }
    }
    let unit = if flags & 0x80 != 0 { 2 } else { 1 };
    for bit in [0x04, 0x08, 0x10, 0x20, 0x40] {
        if flags & bit != 0 {
            pos += 2 + usize::from(u16_le(data, pos)?) * unit;
        }
    }
    for _ in 0..64 {
        match u32_le(data, pos) {
            Some(size) if size >= 4 => pos += size as usize,
            Some(_) => {
                return Some(p.with_len(Some(pos as u64 + 4)));
            }
            None => break,
        }
    }
    p.damaged(Damage::truncated("shortcut structure ends early"));
    Some(p.with_structure(0.6))
}

pub fn prefetch(data: &[u8]) -> Option<Probe> {
    let version = u32_le(data, 0)?;
    if !matches!(version, 17 | 23 | 26 | 30 | 31) {
        return None;
    }
    let mut p = Probe::certain(TypeId::Prefetch).with_len(u32_le(data, 12).map(u64::from));
    p.property("executable", utf16le(data.get(16..76)?));
    p.property("format_version", version);
    Some(p)
}

pub fn prefetch_mam(data: &[u8]) -> Option<Probe> {
    let size = u32_le(data, 4)?;
    let mut p = Probe::new(TypeId::PrefetchCompressed, Confidence::new(0.9));
    p.property("uncompressed_size", size);
    p.note("Xpress-Huffman compressed prefetch");
    Some(p)
}

/// Allocated size of a plausible NTFS FILE record at the start of `rec`.
pub fn mft_record(rec: &[u8]) -> Option<u32> {
    if rec.get(..4)? != b"FILE" {
        return None;
    }
    let usa = u16_le(rec, 4)?;
    let attrs = u16_le(rec, 20)?;
    let used = u32_le(rec, 24)?;
    let alloc = u32_le(rec, 28)?;
    let ok = matches!(usa, 0x2A | 0x30) && matches!(alloc, 1024 | 4096) && used <= alloc && attrs >= 0x30 && u32::from(attrs) < used;
    ok.then_some(alloc)
}

pub fn mft(data: &[u8]) -> Option<Probe> {
    let size = mft_record(data)? as usize;
    let mut records = 0;
    let mut bad = 0;
    let mut end = 0;
    for (i, rec) in data.chunks_exact(size).enumerate() {
        if mft_record(rec).is_some() {
            records += 1;
            end = (i + 1) * size;
        } else if !rec.iter().all(|b| *b == 0) {
            bad += 1;
        }
    }
    let mut p = Probe::new(TypeId::NtfsMft, Confidence::new(0.85)).with_structure(ratio(records, records + bad));
    p.item(InnerKind::Object, format!("{records} FILE records"), Some(records as u64));
    Some(p.with_len(Some(end as u64)))
}

pub fn index_dat(data: &[u8]) -> Option<Probe> {
    let version = String::from_utf8_lossy(data.get(24..27)?).into_owned();
    let mut p = Probe::certain(TypeId::IeIndexDat).with_len(u32_le(data, 0x1C).map(u64::from));
    p.property("version", version);
    let urls = memmem::find_iter(data, b"URL ").filter(|p| p % 128 == 0).count();
    p.item(InnerKind::Object, format!("{urls} URL records"), Some(urls as u64));
    Some(p)
}
