//! Windows registry hive (`regf`) reader: base block, hbins, nk/vk/lf/lh/li/ri/db cells.
//!
//! Every cell access is bounds-checked; broken cells are skipped and reported as damage, and a
//! broken root pointer falls back to scanning the bins for the hive root key.

use crate::text::{ansi, filetime_at};
use std::cell::RefCell;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_kernel::{ByteRange, Damage, Timestamp};

const BASE: usize = 0x1000;
const KEY_COMP_NAME: u16 = 0x20;
const KEY_HIVE_ENTRY: u16 = 0x04;
const VALUE_COMP_NAME: u16 = 0x01;
const MAX_LIST_DEPTH: u8 = 3;
const DB_SEGMENT: usize = 16_344;

pub(crate) const REG_SZ: u32 = 1;
pub(crate) const REG_EXPAND_SZ: u32 = 2;
pub(crate) const REG_DWORD: u32 = 4;
pub(crate) const REG_MULTI_SZ: u32 = 7;
pub(crate) const REG_QWORD: u32 = 11;

pub(crate) struct Hive<'a> {
    data: &'a [u8],
    root: Option<u32>,
    damage: RefCell<Vec<Damage>>,
}

/// A parsed `nk` cell.
#[derive(Debug, Clone)]
pub(crate) struct Key {
    pub name: String,
    pub last_write: Option<Timestamp>,
    subkey_count: u32,
    subkey_list: u32,
    value_count: u32,
    value_list: u32,
}

/// A parsed `vk` cell with its data resolved.
#[derive(Debug, Clone)]
pub(crate) struct Value {
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
}

impl Value {
    /// REG_SZ / REG_EXPAND_SZ as UTF-16 (also tolerates ANSI data written by old software:
    /// UTF-16 text has its high bytes in a few code-page blocks, ANSI text does not).
    pub fn string(&self) -> Option<String> {
        if !matches!(self.kind, REG_SZ | REG_EXPAND_SZ) {
            return None;
        }
        let d = &self.data;
        let wide = d.len().is_multiple_of(2) && d.iter().skip(1).step_by(2).all(|b| *b <= 0x05 || *b == 0x20 || *b == 0x30);
        let s = if wide { strata_kernel::bytes::utf16le(d) } else { ansi(d) };
        (!s.is_empty()).then_some(s)
    }

    pub fn multi_string(&self) -> Vec<String> {
        crate::text::utf16_list(&self.data, usize::MAX)
    }

    pub fn dword(&self) -> Option<u32> {
        u32_le(&self.data, 0)
    }

    pub fn qword(&self) -> Option<u64> {
        strata_kernel::bytes::u64_le(&self.data, 0)
    }

    /// Readable rendering for reports.
    pub fn display(&self) -> String {
        match self.kind {
            REG_DWORD => self.dword().map(|v| v.to_string()).unwrap_or_default(),
            REG_QWORD => self.qword().map(|v| v.to_string()).unwrap_or_default(),
            REG_MULTI_SZ => self.multi_string().join("; "),
            _ => self.string().unwrap_or_else(|| format!("<{} bytes>", self.data.len())),
        }
    }
}

impl<'a> Hive<'a> {
    pub fn is_regf(data: &[u8]) -> bool {
        data.starts_with(b"regf")
    }

    /// `None` when the bytes hold neither a base block nor any hbin.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let hive = Self { data, root: None, damage: RefCell::new(Vec::new()) };
        let has_bins = data.get(BASE..BASE + 4) == Some(b"hbin");
        if !Self::is_regf(data) && !has_bins {
            return None;
        }
        if !Self::is_regf(data) {
            hive.note(Damage::corrupt(ByteRange::new(0, 4), "regf base block missing"));
        }
        hive.check_bins();
        let declared = u32_le(data, 0x24).filter(|&off| hive.key(off).is_some());
        let root = declared.or_else(|| {
            hive.note(Damage::corrupt(ByteRange::new(0x24, 4), "root key pointer broken; scanning bins"));
            hive.find_root()
        });
        Some(Self { root, ..hive })
    }

    pub fn take_damage(&self) -> Vec<Damage> {
        std::mem::take(&mut self.damage.borrow_mut())
    }

    fn note(&self, d: Damage) {
        let mut v = self.damage.borrow_mut();
        if v.len() < 256 {
            v.push(d);
        }
    }

    /// Walk hbins, reporting bad headers and resynchronising on the next 4 KiB boundary.
    fn check_bins(&self) {
        let mut off = BASE;
        while off + 0x20 <= self.data.len() {
            let size = u32_le(self.data, off + 8).unwrap_or(0) as usize;
            if &self.data[off..off + 4] == b"hbin" && size >= 0x1000 && size.is_multiple_of(0x1000) {
                off += size;
            } else {
                self.note(Damage::corrupt(ByteRange::new(off as u64, 0x1000), "bad hbin header"));
                off += 0x1000;
            }
        }
    }

    fn find_root(&self) -> Option<u32> {
        let mut off = BASE + 0x20;
        while off + 8 < self.data.len() {
            let rel = u32::try_from(off - BASE).ok()?;
            if self.data.get(off + 4..off + 6) == Some(b"nk")
                && u16_le(self.data, off + 6).is_some_and(|f| f & KEY_HIVE_ENTRY != 0)
                && self.key(rel).is_some()
            {
                return Some(rel);
            }
            off += 8;
        }
        None
    }

    /// Payload of the cell at hive offset `off` (allocated or free).
    fn cell(&self, off: u32) -> Option<&'a [u8]> {
        let abs = BASE.checked_add(off as usize)?;
        let raw = i32::from_le_bytes(strata_kernel::bytes::array(self.data, abs)?);
        let len = raw.unsigned_abs() as usize;
        if len < 8 || abs.checked_add(len)? > self.data.len() {
            self.note(Damage::corrupt(ByteRange::new(abs as u64, 4), "bad cell size"));
            return None;
        }
        self.data.get(abs + 4..abs + len)
    }

    pub fn root(&self) -> Option<Key> {
        self.root.and_then(|r| self.key(r))
    }

    fn key(&self, off: u32) -> Option<Key> {
        let c = self.cell(off)?;
        if c.get(0..2)? != b"nk" {
            return None;
        }
        let flags = u16_le(c, 2)?;
        let name_len = usize::from(u16_le(c, 0x48)?);
        let raw = c.get(0x4C..0x4C + name_len)?;
        let name = if flags & KEY_COMP_NAME != 0 { ansi(raw) } else { strata_kernel::bytes::utf16le(raw) };
        Some(Key {
            name,
            last_write: filetime_at(c, 4),
            subkey_count: u32_le(c, 0x14)?,
            subkey_list: u32_le(c, 0x1C)?,
            value_count: u32_le(c, 0x24)?,
            value_list: u32_le(c, 0x28)?,
        })
    }

    pub fn subkeys(&self, key: &Key) -> Vec<Key> {
        let mut offs = Vec::new();
        if key.subkey_count > 0 {
            self.collect_list(key.subkey_list, 0, &mut offs);
        }
        offs.into_iter().filter_map(|o| self.key(o)).collect()
    }

    fn collect_list(&self, off: u32, depth: u8, out: &mut Vec<u32>) {
        let Some(c) = self.cell(off) else { return };
        let count = usize::from(u16_le(c, 2).unwrap_or(0));
        let (stride, nested) = match c.get(0..2) {
            Some(b"lf") | Some(b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => {
                self.note(Damage::new(strata_kernel::DamageKind::Corrupt, None, format!("unknown subkey list at {off:#x}")));
                return;
            }
        };
        for i in 0..count {
            let Some(o) = u32_le(c, 4 + stride * i) else { break };
            if nested {
                if depth < MAX_LIST_DEPTH {
                    self.collect_list(o, depth + 1, out);
                }
            } else {
                out.push(o);
            }
        }
    }

    pub fn subkey(&self, key: &Key, name: &str) -> Option<Key> {
        self.subkeys(key).into_iter().find(|k| k.name.eq_ignore_ascii_case(name))
    }

    /// Open a `\`-separated path below the root.
    pub fn open(&self, path: &str) -> Option<Key> {
        let mut k = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            k = self.subkey(&k, part)?;
        }
        Some(k)
    }

    pub fn values(&self, key: &Key) -> Vec<Value> {
        if key.value_count == 0 {
            return Vec::new();
        }
        let Some(list) = self.cell(key.value_list) else { return Vec::new() };
        (0..key.value_count as usize)
            .map_while(|i| u32_le(list, 4 * i))
            .filter_map(|o| self.value_at(o))
            .collect()
    }

    pub fn value(&self, key: &Key, name: &str) -> Option<Value> {
        self.values(key).into_iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    fn value_at(&self, off: u32) -> Option<Value> {
        let c = self.cell(off)?;
        if c.get(0..2)? != b"vk" {
            return None;
        }
        let name_len = usize::from(u16_le(c, 2)?);
        let raw_len = u32_le(c, 4)?;
        let flags = u16_le(c, 0x10)?;
        let raw_name = c.get(0x14..0x14 + name_len).unwrap_or(&[]);
        let name = if flags & VALUE_COMP_NAME != 0 { ansi(raw_name) } else { strata_kernel::bytes::utf16le(raw_name) };
        let kind = u32_le(c, 0x0C)?;
        let data = if raw_len & 0x8000_0000 != 0 {
            let n = ((raw_len & 0x7fff_ffff) as usize).min(4);
            c.get(8..8 + n)?.to_vec()
        } else {
            self.value_data(u32_le(c, 8)?, raw_len as usize)
        };
        Some(Value { name, kind, data })
    }

    fn value_data(&self, off: u32, len: usize) -> Vec<u8> {
        let Some(c) = self.cell(off) else { return Vec::new() };
        if len > DB_SEGMENT && c.get(0..2) == Some(b"db") {
            let segments = usize::from(u16_le(c, 2).unwrap_or(0));
            let Some(list) = u32_le(c, 4).and_then(|o| self.cell(o)) else { return Vec::new() };
            let mut out = Vec::with_capacity(len.min(1 << 20));
            for i in 0..segments {
                let Some(seg) = u32_le(list, 4 * i).and_then(|o| self.cell(o)) else { break };
                out.extend_from_slice(&seg[..seg.len().min(DB_SEGMENT)]);
            }
            out.truncate(len);
            return out;
        }
        c[..c.len().min(len)].to_vec()
    }
}

#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod tests {
    use super::testutil::{HiveBuilder, sz};
    use super::*;

    #[test]
    fn navigate_values_and_big_data() {
        let mut b = HiveBuilder::new();
        let big: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        b.value("Software\\Test", "Name", REG_SZ, &sz("hello"));
        b.value("Software\\Test", "Num", REG_DWORD, &7u32.to_le_bytes());
        b.value("Software\\Test", "Big", 3, &big);
        let bytes = b.build();
        let hive = Hive::parse(&bytes).unwrap();
        let k = hive.open("software\\TEST").unwrap();
        assert_eq!(hive.value(&k, "name").unwrap().string().as_deref(), Some("hello"));
        assert_eq!(hive.value(&k, "Num").unwrap().dword(), Some(7));
        assert_eq!(hive.value(&k, "Big").unwrap().data, big);
        assert!(hive.take_damage().is_empty());
    }

    #[test]
    fn broken_root_pointer_recovers() {
        let mut b = HiveBuilder::new();
        b.value("A\\B", "x", REG_SZ, &sz("y"));
        let mut bytes = b.build();
        bytes[0x24..0x28].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let hive = Hive::parse(&bytes).unwrap();
        assert!(hive.open("A\\B").is_some());
        assert!(!hive.take_damage().is_empty());
    }

    #[test]
    fn garbage_and_truncation() {
        let mut b = HiveBuilder::new();
        b.value("A\\B\\C", "x", REG_SZ, &sz("y"));
        let bytes = b.build();
        for cut in [0, 4, 0x1000, 0x1004, 0x1020, 0x1100, bytes.len() - 1] {
            if let Some(h) = Hive::parse(&bytes[..cut]) {
                let _ = h.open("A\\B\\C").map(|k| h.values(&k));
            }
        }
        let mut junk = bytes.clone();
        for (i, x) in junk.iter_mut().enumerate().skip(0x1020) {
            *x = (i * 7 % 256) as u8;
        }
        let h = Hive::parse(&junk).unwrap();
        let _ = h.open("A\\B\\C");
    }
}
