//! SQLite 3: header, b-tree page plausibility, schema (sqlite_master) table names.

use super::wallet::{bitcoin_records, refine_bitcoin};
use crate::probe::Probe;
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use memchr::memmem;
use strata_kernel::bytes::{u16_be, u32_be, u8_at};
use strata_kernel::{ByteRange, Confidence, Damage};

pub const MAGIC: &[u8] = b"SQLite format 3\0";
const MAX_PAGES_VISITED: usize = 2000;

/// SQLite varint: (value, length).
fn varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..9 {
        let b = *data.get(pos + i)?;
        if i == 8 {
            return Some(((v << 8) | u64::from(b), 9));
        }
        v = (v << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn serial_size(t: u64) -> usize {
    match t {
        0 | 8 | 9 | 10 | 11 => 0,
        1..=4 => t as usize,
        5 => 6,
        6 | 7 => 8,
        n => ((n - 12) / 2) as usize,
    }
}

/// Is `page` (with its b-tree header at `hdr`) a plausible b-tree page of `page_size`?
pub fn btree_page_plausible(page: &[u8], hdr: usize, page_size: usize) -> bool {
    let Some(kind) = u8_at(page, hdr) else { return false };
    if !matches!(kind, 2 | 5 | 10 | 13) {
        return false;
    }
    let (Some(cells), Some(content), Some(frag)) = (u16_be(page, hdr + 3), u16_be(page, hdr + 5), u8_at(page, hdr + 7)) else {
        return false;
    };
    let header_len = if matches!(kind, 2 | 5) { 12 } else { 8 };
    let content = if content == 0 { 65536 } else { usize::from(content) };
    let ptr_end = hdr + header_len + usize::from(cells) * 2;
    cells > 0 && frag <= 60 && content <= page_size && ptr_end <= content
}

/// Header facts.
pub struct Header {
    pub page_size: usize,
    pub page_count: u32,
    pub declared_valid: bool,
}

impl Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !data.starts_with(MAGIC) {
            return None;
        }
        let raw = u16_be(data, 16)?;
        let page_size = if raw == 1 { 65536 } else { usize::from(raw) };
        if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
            return None;
        }
        if u8_at(data, 21)? != 64 || u8_at(data, 22)? != 32 || u8_at(data, 23)? != 32 {
            return None;
        }
        let page_count = u32_be(data, 28)?;
        let declared_valid = page_count > 0 && u32_be(data, 24)? == u32_be(data, 92)?;
        Some(Self { page_size, page_count, declared_valid })
    }

    pub fn declared_len(&self) -> Option<u64> {
        self.declared_valid.then(|| u64::from(self.page_count) * self.page_size as u64)
    }
}

/// One sqlite_master row.
#[derive(Debug, Clone)]
pub struct SchemaRow {
    pub kind: String,
    pub name: String,
    pub sql: String,
}

fn parse_record(payload: &[u8]) -> Option<Vec<String>> {
    let (header_len, mut p) = varint(payload, 0)?;
    let mut types = Vec::new();
    while p < header_len as usize && types.len() < 8 {
        let (t, l) = varint(payload, p)?;
        types.push(t);
        p += l;
    }
    let mut body = header_len as usize;
    let mut out = Vec::new();
    for t in types {
        let size = serial_size(t);
        let raw = payload.get(body..body.saturating_add(size).min(payload.len())).unwrap_or_default();
        out.push(if t >= 13 && t % 2 == 1 { String::from_utf8_lossy(raw).into_owned() } else { String::new() });
        body = body.saturating_add(size);
    }
    Some(out)
}

/// Read sqlite_master rows starting at page 1.
pub fn schema(data: &[u8], page_size: usize) -> (Vec<SchemaRow>, Vec<Damage>) {
    let mut rows = Vec::new();
    let mut damage = Vec::new();
    let mut stack = vec![(1u32, 0usize)];
    let mut visited = 0;
    while let Some((page_no, depth)) = stack.pop() {
        visited += 1;
        if visited > MAX_PAGES_VISITED || depth > 6 || page_no == 0 {
            break;
        }
        let start = (page_no as usize - 1) * page_size;
        let Some(page) = data.get(start..start + page_size) else {
            damage.push(Damage::missing(Some(ByteRange::new(start as u64, page_size as u64)), "schema page beyond data"));
            continue;
        };
        let hdr = if page_no == 1 { 100 } else { 0 };
        if !btree_page_plausible(page, hdr, page_size) {
            damage.push(Damage::corrupt(ByteRange::new(start as u64, page_size as u64), "schema b-tree page invalid"));
            continue;
        }
        let interior = page[hdr] == 5;
        let cells = usize::from(u16_be(page, hdr + 3).unwrap_or(0));
        let ptrs = hdr + if interior { 12 } else { 8 };
        if interior && let Some(right) = u32_be(page, hdr + 8) {
            stack.push((right, depth + 1));
        }
        for i in 0..cells {
            let Some(cell) = u16_be(page, ptrs + i * 2).map(usize::from) else { break };
            if interior {
                if let Some(child) = u32_be(page, cell) {
                    stack.push((child, depth + 1));
                }
                continue;
            }
            let Some((len, a)) = varint(page, cell) else { continue };
            let Some((_, b)) = varint(page, cell + a) else { continue };
            let from = cell + a + b;
            let payload = page.get(from..from.saturating_add(len as usize).min(page.len())).unwrap_or_default();
            if let Some(cols) = parse_record(payload)
                && cols.len() >= 2
            {
                let sql = cols.get(4).cloned().unwrap_or_default();
                rows.push(SchemaRow { kind: cols[0].clone(), name: cols[1].clone(), sql });
            }
        }
    }
    (rows, damage)
}

/// Table names from `CREATE TABLE` statements anywhere in `data` (headerless fallback).
pub fn create_statements(data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for pos in memmem::find_iter(data, b"CREATE TABLE ").take(1000) {
        let rest = data.get(pos + 13..pos + 13 + 128).unwrap_or_else(|| data.get(pos + 13..).unwrap_or_default());
        let rest = rest.strip_prefix(b"IF NOT EXISTS ").unwrap_or(rest);
        let name: String = rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'"' | b'`' | b'[' | b']' | b'.'))
            .map(|b| char::from(*b))
            .filter(|c| !matches!(c, '"' | '`' | '[' | ']'))
            .collect();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

pub fn validate(data: &[u8]) -> Option<Probe> {
    let h = Header::parse(data)?;
    let mut p = Probe::certain(TypeId::Sqlite).with_len(h.declared_len());
    p.property("page_size", h.page_size);
    p.property("pages", h.page_count);
    let (rows, damage) = schema(data, h.page_size);
    if rows.is_empty() {
        let names = create_statements(data);
        p = p.with_structure(if names.is_empty() { 0.4 } else { 0.7 });
        for n in names {
            p.item(InnerKind::Table, n, None);
        }
    } else {
        for r in rows.iter().filter(|r| r.kind == "table") {
            p.item(InnerKind::Table, r.name.clone(), None);
        }
    }
    if !damage.is_empty() && !rows.is_empty() {
        p = p.with_structure(0.8);
    }
    p.damage.extend(damage);
    if rows.iter().any(|r| r.name == "main" && r.sql.contains("key BLOB")) {
        p = refine_bitcoin(p, &bitcoin_records(data), Confidence::new(0.95));
    }
    Some(p)
}
