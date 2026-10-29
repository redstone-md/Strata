//! OLE2 / Compound File Binary: header, FAT, directory, subtype by stream names.

use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at};
use strata_kernel::{ByteRange, Confidence, Damage};

const FREE: u32 = 0xFFFF_FFFF;
const END: u32 = 0xFFFF_FFFE;
const MAX_SECT: u32 = 0xFFFF_FFFA;
const MAX_DIR_SECTORS: usize = 4096;

/// One 128-byte directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    /// 1 storage, 2 stream, 5 root.
    pub kind: u8,
    pub size: u64,
}

impl DirEntry {
    /// Parse a directory entry; `None` for empty or implausible slots.
    pub fn parse(e: &[u8]) -> Option<Self> {
        let name_len = usize::from(u16_le(e, 64)?);
        let kind = u8_at(e, 66)?;
        let color = u8_at(e, 67)?;
        if !matches!(kind, 1 | 2 | 5) || color > 1 || !(4..=64).contains(&name_len) || !name_len.is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = e.get(..name_len - 2)?.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        if units.contains(&0) || u16_le(e, name_len - 2)? != 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&units);
        Some(Self { name, kind, size: u64_le(e, 120)? })
    }
}

/// Map stream names to the specific OLE application format.
pub fn classify_names<'a>(names: impl IntoIterator<Item = &'a str>) -> TypeId {
    let mut id = TypeId::Ole2;
    for n in names {
        id = match n {
            "WordDocument" => return TypeId::Doc,
            "Workbook" | "Book" => return TypeId::Xls,
            "PowerPoint Document" => return TypeId::Ppt,
            n if n.starts_with("__substg1.0_") || n.starts_with("__nameid_version1.0") => TypeId::Msg,
            "Catalog" if id == TypeId::Ole2 => TypeId::ThumbsDb,
            _ => id,
        };
    }
    id
}

struct Header {
    sector: usize,
    fat_sectors: u32,
    first_dir: u32,
    first_difat: u32,
    difat_sectors: u32,
}

impl Header {
    fn parse(data: &[u8]) -> Option<Self> {
        let major = u16_le(data, 26)?;
        let shift = u16_le(data, 30)?;
        if u16_le(data, 28)? != 0xFFFE || !matches!((major, shift), (3, 9) | (4, 12)) {
            return None;
        }
        Some(Self {
            sector: 1 << shift,
            fat_sectors: u32_le(data, 44)?,
            first_dir: u32_le(data, 48)?,
            first_difat: u32_le(data, 68)?,
            difat_sectors: u32_le(data, 72)?,
        })
    }

    fn offset(&self, sector: u32) -> usize {
        (sector as usize + 1).saturating_mul(self.sector)
    }
}

struct Compound<'a> {
    data: &'a [u8],
    h: Header,
    fat: Vec<u32>,
    damage: Vec<Damage>,
}

impl<'a> Compound<'a> {
    fn new(data: &'a [u8], h: Header) -> Self {
        let mut c = Self { data, h, fat: Vec::new(), damage: Vec::new() };
        c.load_fat();
        c
    }

    fn sector(&self, n: u32) -> Option<&'a [u8]> {
        let off = self.h.offset(n);
        self.data.get(off..off + self.h.sector)
    }

    fn difat(&self) -> Vec<u32> {
        let mut out: Vec<u32> = (0..109).filter_map(|i| u32_le(self.data, 76 + i * 4)).collect();
        let mut next = self.h.first_difat;
        let per = self.h.sector / 4 - 1;
        for _ in 0..self.h.difat_sectors.min(4096) {
            let Some(s) = (next <= MAX_SECT).then(|| self.sector(next)).flatten() else { break };
            out.extend((0..per).filter_map(|i| u32_le(s, i * 4)));
            next = u32_le(s, per * 4).unwrap_or(END);
        }
        out.retain(|s| *s <= MAX_SECT);
        out.truncate(self.h.fat_sectors as usize);
        out
    }

    fn load_fat(&mut self) {
        for s in self.difat() {
            match self.sector(s) {
                Some(bytes) if !bytes.iter().all(|b| *b == 0) => {
                    self.fat.extend(bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)));
                }
                _ => {
                    let off = self.h.offset(s) as u64;
                    self.damage.push(Damage::missing(Some(ByteRange::new(off, self.h.sector as u64)), "FAT sector unreadable"));
                    self.fat.extend(std::iter::repeat_n(FREE, self.h.sector / 4));
                }
            }
        }
    }

    /// Directory sectors via the FAT chain, or contiguous sectors when the FAT is damaged.
    fn dir_sectors(&self) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = self.h.first_dir;
        while cur <= MAX_SECT && out.len() < MAX_DIR_SECTORS && !out.contains(&cur) {
            out.push(cur);
            match self.fat.get(cur as usize) {
                Some(next) if *next != FREE => cur = *next,
                _ => break,
            }
        }
        if out.len() == 1 && self.fat.get(self.h.first_dir as usize).is_none_or(|n| *n == FREE) {
            // FAT unusable: assume the directory is contiguous.
            let mut s = self.h.first_dir + 1;
            while out.len() < 64 && self.sector(s).is_some_and(|b| DirEntry::parse(b).is_some()) {
                out.push(s);
                s += 1;
            }
        }
        out
    }

    fn entries(&self) -> (Vec<DirEntry>, usize) {
        let mut entries = Vec::new();
        let mut slots = 0;
        for s in self.dir_sectors() {
            let Some(bytes) = self.sector(s) else { break };
            for e in bytes.as_chunks::<128>().0 {
                if e.iter().all(|b| *b == 0) {
                    continue;
                }
                slots += 1;
                entries.extend(DirEntry::parse(e.as_slice()));
            }
        }
        (entries, slots)
    }

    /// File length implied by the highest used FAT entry.
    fn declared_len(&self) -> Option<u64> {
        let last = self.fat.iter().rposition(|v| *v != FREE)?;
        Some((last as u64 + 2) * self.h.sector as u64)
    }
}

pub fn validate(data: &[u8]) -> Option<Probe> {
    let header = Header::parse(data)?;
    let c = Compound::new(data, header);
    let (entries, slots) = c.entries();
    let id = classify_names(entries.iter().map(|e| e.name.as_str()));
    let mut p = Probe::certain(id).with_len(c.declared_len());
    if entries.is_empty() {
        p = p.with_confidence(Confidence::new(0.85)).with_structure(0.3);
        p.damaged(Damage::missing(None, "directory unreadable"));
    } else {
        let fat_ok = 1.0 - c.damage.len() as f32 / (c.damage.len() + c.difat().len()).max(1) as f32;
        p = p.with_structure(ratio(entries.len(), slots) * fat_ok.max(0.1));
    }
    p.damage.extend(c.damage);
    for e in entries.iter().filter(|e| e.kind != 5).take(2000) {
        let kind = if e.kind == 1 { InnerKind::Object } else { InnerKind::Stream };
        p.item(kind, e.name.clone(), (e.kind == 2).then_some(e.size));
    }
    Some(p)
}
