//! Berkeley DB btree reader (no libdb): walks every leaf page and yields key/value records.
//! A damaged or headless file is handled by salvage mode, which guesses the page size and
//! parses every page that looks like a leaf, item by item.

mod page;
#[cfg(test)]
pub(crate) mod fixture;

pub use page::{Endian, MetaPage, looks_like_leaf};
use page::{leaf_item, valid_page_size, Item, PageHeader, HEADER_LEN, P_OVERFLOW};
use strata_kernel::{ByteRange, Damage, DamageKind};

/// One key/value pair from a leaf page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdbRecord {
    key: Vec<u8>,
    value: Vec<u8>,
    page: u32,
    deleted: bool,
}

impl BdbRecord {
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Page index (file offset / page size) the record was read from.
    pub fn page(&self) -> u32 {
        self.page
    }

    /// The item carried BDB's deleted flag (still recovered).
    pub fn deleted(&self) -> bool {
        self.deleted
    }
}

/// Parsed (or salvaged) Berkeley DB file.
#[derive(Debug, Clone)]
pub struct BdbFile {
    meta: Option<MetaPage>,
    endian: Endian,
    page_size: usize,
    records: Vec<BdbRecord>,
    damage: Vec<Damage>,
    salvaged: bool,
}

/// Page sizes tried by salvage, most likely first (Bitcoin Core uses 4096).
const SALVAGE_SIZES: [usize; 8] = [4096, 8192, 16384, 32768, 65536, 2048, 1024, 512];
/// Longest overflow chain followed (guards against cycles).
const MAX_OVERFLOW_PAGES: usize = 4096;

impl BdbFile {
    /// Parse via the meta page; falls back to salvage when it is unusable.
    pub fn parse(data: &[u8]) -> Option<Self> {
        match MetaPage::parse(data) {
            Some(meta) => Some(Self::walk(data, Some(meta), meta.endian, meta.page_size, false)),
            None => Self::salvage(data),
        }
    }

    /// Ignore the meta page: guess endianness and page size from leaf-looking pages.
    pub fn salvage(data: &[u8]) -> Option<Self> {
        let meta = MetaPage::parse(data);
        let mut best: Option<(usize, Endian, usize)> = None;
        for endian in [Endian::Little, Endian::Big] {
            for size in meta.map(|m| m.page_size).into_iter().chain(SALVAGE_SIZES) {
                let leaves = data.chunks(size).filter(|p| looks_like_leaf(p, endian)).count();
                if leaves > best.map_or(0, |b| b.0) {
                    best = Some((leaves, endian, size));
                }
            }
        }
        let (_, endian, size) = best?;
        let mut file = Self::walk(data, meta, endian, size, true);
        if meta.is_none() {
            file.damage.insert(0, Damage::corrupt(ByteRange::new(0, 512.min(data.len() as u64)), "BDB meta page missing or invalid; salvaged"));
        }
        (!file.records.is_empty()).then_some(file)
    }

    fn walk(data: &[u8], meta: Option<MetaPage>, endian: Endian, page_size: usize, salvaged: bool) -> Self {
        let mut file = Self { meta, endian, page_size, records: Vec::new(), damage: Vec::new(), salvaged };
        if !valid_page_size(page_size) {
            return file;
        }
        let available = data.len() / page_size;
        if let Some(m) = meta {
            let declared = (m.last_pgno as usize).saturating_add(1);
            if declared > available {
                file.damage.push(Damage::new(
                    DamageKind::Truncated,
                    None,
                    format!("meta declares {declared} pages, file holds {available}"),
                ));
            }
        }
        for (index, page) in data.chunks_exact(page_size).enumerate() {
            if !looks_like_leaf(page, endian) {
                continue;
            }
            file.read_leaf(data, page, index as u32);
        }
        file
    }

    fn page_range(&self, index: u32) -> ByteRange {
        ByteRange::new(u64::from(index) * self.page_size as u64, self.page_size as u64)
    }

    fn read_leaf(&mut self, data: &[u8], page: &[u8], index: u32) {
        let e = self.endian;
        let Some(h) = PageHeader::parse(page, e) else { return };
        if h.pgno != index {
            self.damage.push(Damage::corrupt(self.page_range(index), format!("leaf page {index} claims pgno {}", h.pgno)));
        }
        let entries = usize::from(h.entries);
        let mut bad = 0usize;
        for pair in 0..entries / 2 {
            let key = leaf_item(page, e, 2 * pair).and_then(|i| self.item_bytes(data, &i).map(|b| (b, i.deleted())));
            let value = leaf_item(page, e, 2 * pair + 1).and_then(|i| self.item_bytes(data, &i).map(|b| (b, i.deleted())));
            match (key, value) {
                (Some((key, kd)), Some((value, vd))) => {
                    self.records.push(BdbRecord { key, value, page: index, deleted: kd || vd })
                }
                _ => bad += 1,
            }
        }
        if bad > 0 || entries % 2 == 1 {
            self.damage.push(Damage::corrupt(self.page_range(index), format!("leaf page {index}: {bad} unreadable item pairs")));
        }
    }

    fn item_bytes(&mut self, data: &[u8], item: &Item<'_>) -> Option<Vec<u8>> {
        match item {
            Item::Inline { data, .. } => Some(data.to_vec()),
            Item::Overflow { pgno, total_len, .. } => self.read_overflow(data, *pgno, *total_len as usize),
        }
    }

    fn read_overflow(&mut self, data: &[u8], first: u32, total: usize) -> Option<Vec<u8>> {
        let total = total.min(data.len());
        let max_pages = MAX_OVERFLOW_PAGES.min(data.len() / self.page_size + 1);
        let mut out = Vec::with_capacity(total.min(1 << 20));
        let mut pgno = first;
        for _ in 0..max_pages {
            if out.len() >= total {
                break;
            }
            let start = (pgno as usize).checked_mul(self.page_size)?;
            let Some(page) = data.get(start..start.checked_add(self.page_size)?) else {
                self.damage.push(Damage::missing(Some(self.page_range(pgno)), "overflow page beyond end of file"));
                return (!out.is_empty()).then_some(out);
            };
            let h = PageHeader::parse(page, self.endian)?;
            if h.page_type != P_OVERFLOW {
                self.damage.push(Damage::corrupt(self.page_range(pgno), "overflow chain points at non-overflow page"));
                return (!out.is_empty()).then_some(out);
            }
            let take = usize::from(h.hf_offset).min(total - out.len());
            out.extend_from_slice(page.get(HEADER_LEN..HEADER_LEN + take)?);
            if h.next_pgno == 0 {
                break;
            }
            pgno = h.next_pgno;
        }
        if out.len() < total {
            self.damage.push(Damage::truncated(format!("overflow item from page {first}: {} of {total} bytes", out.len())));
        }
        Some(out)
    }

    pub fn meta(&self) -> Option<&MetaPage> {
        self.meta.as_ref()
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn records(&self) -> &[BdbRecord] {
        &self.records
    }

    pub fn damage(&self) -> &[Damage] {
        &self.damage
    }

    pub fn salvaged(&self) -> bool {
        self.salvaged
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::BdbBuilder;
    use super::*;

    #[test]
    fn reads_inline_and_overflow_records() {
        let big = vec![0xabu8; 5000];
        let file = BdbBuilder::new(4096)
            .record(b"\x03abc", b"one")
            .record(b"\x03big", &big)
            .build();
        let db = BdbFile::parse(&file).unwrap();
        assert!(!db.salvaged());
        assert_eq!(db.records().len(), 2);
        assert_eq!(db.records()[0].value(), b"one");
        assert_eq!(db.records()[1].value(), big.as_slice());
        assert!(db.damage().is_empty(), "{:?}", db.damage());
    }

    #[test]
    fn salvages_without_meta() {
        let mut file = BdbBuilder::new(4096).record(b"\x01k", b"v").build();
        file[..512].fill(0);
        let db = BdbFile::parse(&file).unwrap();
        assert!(db.salvaged());
        assert_eq!(db.records().len(), 1);
        assert!(!db.damage().is_empty());
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 0x1234_5678u32;
        for len in [0usize, 1, 25, 26, 511, 4096, 9000] {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let _ = BdbFile::parse(&data);
            let _ = BdbFile::salvage(&data);
        }
        let mut file = BdbBuilder::new(512).record(b"\x01k", &[7u8; 2000]).build();
        for i in (0..file.len()).step_by(7) {
            file[i] = file[i].wrapping_mul(31).wrapping_add(3);
            let _ = BdbFile::parse(&file);
        }
    }
}
