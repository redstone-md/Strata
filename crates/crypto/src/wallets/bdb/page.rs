//! Berkeley DB page layout: generic header, btree leaf items, overflow pages.

use strata_kernel::bytes;

/// Page header size (`PAGE` struct) before the item index array.
pub const HEADER_LEN: usize = 26;
#[cfg_attr(not(test), allow(dead_code))]
pub const P_BTREEMETA: u8 = 9;
pub const P_LBTREE: u8 = 5;
pub const P_OVERFLOW: u8 = 7;
pub const B_KEYDATA: u8 = 1;
pub const B_OVERFLOW: u8 = 3;
pub const B_DELETE: u8 = 0x80;
pub const MAGIC_BTREE: u32 = 0x0005_3162;
pub const MAGIC_HASH: u32 = 0x0006_1561;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn u16(self, data: &[u8], off: usize) -> Option<u16> {
        match self {
            Endian::Little => bytes::u16_le(data, off),
            Endian::Big => bytes::u16_be(data, off),
        }
    }

    pub fn u32(self, data: &[u8], off: usize) -> Option<u32> {
        match self {
            Endian::Little => bytes::u32_le(data, off),
            Endian::Big => bytes::u32_be(data, off),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

/// Validated metadata page (page 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaPage {
    pub endian: Endian,
    pub magic: u32,
    pub version: u32,
    pub page_size: usize,
    pub last_pgno: u32,
    pub page_type: u8,
}

impl MetaPage {
    /// Parse a meta page at `data[0]`; `None` unless magic, version and page size are sane.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let raw = bytes::array::<4>(data, 12)?;
        let (endian, magic) = [Endian::Little, Endian::Big].into_iter().find_map(|e| {
            let m = match e {
                Endian::Little => u32::from_le_bytes(raw),
                Endian::Big => u32::from_be_bytes(raw),
            };
            (m == MAGIC_BTREE || m == MAGIC_HASH).then_some((e, m))
        })?;
        let version = endian.u32(data, 16)?;
        let page_size = endian.u32(data, 20)? as usize;
        if !(1..=20).contains(&version) || !valid_page_size(page_size) {
            return None;
        }
        Some(Self {
            endian,
            magic,
            version,
            page_size,
            last_pgno: endian.u32(data, 32)?,
            page_type: bytes::u8_at(data, 25)?,
        })
    }

    pub fn is_btree(&self) -> bool {
        self.magic == MAGIC_BTREE
    }
}

pub fn valid_page_size(size: usize) -> bool {
    (512..=65536).contains(&size) && size.is_power_of_two()
}

/// Generic page header fields.
#[derive(Debug, Clone, Copy)]
pub struct PageHeader {
    pub pgno: u32,
    pub next_pgno: u32,
    pub entries: u16,
    pub hf_offset: u16,
    pub page_type: u8,
}

impl PageHeader {
    pub fn parse(page: &[u8], e: Endian) -> Option<Self> {
        Some(Self {
            pgno: e.u32(page, 8)?,
            next_pgno: e.u32(page, 16)?,
            entries: e.u16(page, 20)?,
            hf_offset: e.u16(page, 22)?,
            page_type: bytes::u8_at(page, 25)?,
        })
    }
}

/// One item on a btree leaf page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item<'a> {
    Inline { data: &'a [u8], deleted: bool },
    Overflow { pgno: u32, total_len: u32, deleted: bool },
}

impl Item<'_> {
    pub fn deleted(&self) -> bool {
        match self {
            Item::Inline { deleted, .. } | Item::Overflow { deleted, .. } => *deleted,
        }
    }
}

/// Item `index` of a leaf page; `None` if its offset or length is out of the page.
pub fn leaf_item(page: &[u8], e: Endian, index: usize) -> Option<Item<'_>> {
    let off = usize::from(e.u16(page, HEADER_LEN + 2 * index)?);
    if off < HEADER_LEN || off >= page.len() {
        return None;
    }
    let ty = bytes::u8_at(page, off + 2)?;
    let deleted = ty & B_DELETE != 0;
    match ty & !B_DELETE {
        B_KEYDATA => {
            let len = usize::from(e.u16(page, off)?);
            let data = page.get(off + 3..off + 3 + len)?;
            Some(Item::Inline { data, deleted })
        }
        B_OVERFLOW => Some(Item::Overflow {
            pgno: e.u32(page, off + 4)?,
            total_len: e.u32(page, off + 8)?,
            deleted,
        }),
        _ => None,
    }
}

/// Heuristic: page looks like a btree leaf (type, entry count within page bounds).
pub fn looks_like_leaf(page: &[u8], e: Endian) -> bool {
    let Some(h) = PageHeader::parse(page, e) else { return false };
    let max_entries = page.len().saturating_sub(HEADER_LEN) / 2;
    h.page_type == P_LBTREE && h.entries > 0 && usize::from(h.entries) <= max_entries
}
