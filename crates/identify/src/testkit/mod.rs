//! Synthetic file builders for tests (this crate and `strata-carve`). Not part of the API.

use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

mod media;

pub use media::{jpeg, ole, pdf, pe, png};

fn le16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn le32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Deterministic pseudo-random bytes (xorshift).
pub fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}

/// Readable filler text.
pub fn lorem(len: usize) -> Vec<u8> {
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor. "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).expect("in-memory write");
    e.finish().expect("in-memory finish")
}

/// ZIP with (name, content, deflate?) members, central directory and end record.
pub fn zip(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, compress) in members {
        let (method, payload) = if *compress { (8u16, deflate(data)) } else { (0u16, data.to_vec()) };
        let crc = crc32fast::hash(data);
        let offset = out.len() as u32;
        for (buf, local) in [(&mut out, true), (&mut central, false)] {
            buf.extend_from_slice(if local { b"PK\x03\x04" } else { b"PK\x01\x02" });
            if !local {
                le16(buf, 20);
            }
            for v in [20u16, 0, method, 0, 0x5021] {
                le16(buf, v);
            }
            for v in [crc, payload.len() as u32, data.len() as u32] {
                le32(buf, v);
            }
            le16(buf, name.len() as u16);
            le16(buf, 0);
            if !local {
                for v in [0u16, 0, 0] {
                    le16(buf, v);
                }
                le32(buf, 0);
                le32(buf, offset);
            }
            buf.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&payload);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    le16(&mut out, members.len() as u16);
    le16(&mut out, members.len() as u16);
    le32(&mut out, central.len() as u32);
    le32(&mut out, cd_offset);
    le16(&mut out, 0);
    out
}

fn sqlite_varint(v: &mut Vec<u8>, x: u64) {
    if x < 0x80 {
        v.push(x as u8);
    } else {
        v.push(0x80 | ((x >> 7) & 0x7F) as u8);
        v.push((x & 0x7F) as u8);
    }
}

/// Encode a record of text columns; column 3 becomes the int `rootpage` when given.
fn sqlite_record(cols: &[&[u8]], rootpage: Option<u8>) -> Vec<u8> {
    let mut types = Vec::new();
    for (i, c) in cols.iter().enumerate() {
        if i == 3 && rootpage.is_some() {
            sqlite_varint(&mut types, 1);
        } else {
            sqlite_varint(&mut types, 13 + 2 * c.len() as u64);
        }
    }
    let mut rec = Vec::new();
    sqlite_varint(&mut rec, types.len() as u64 + 1);
    rec.extend_from_slice(&types);
    for (i, c) in cols.iter().enumerate() {
        match (i, rootpage) {
            (3, Some(r)) => rec.push(r),
            _ => rec.extend_from_slice(c),
        }
    }
    rec
}

/// A table-leaf page holding `records`; `hdr` is 100 on page 1.
fn sqlite_leaf(page_size: usize, hdr: usize, records: &[Vec<u8>]) -> Vec<u8> {
    let mut page = vec![0u8; page_size];
    let mut content = page_size;
    let mut ptrs = Vec::new();
    for (rowid, rec) in records.iter().enumerate() {
        let mut cell = Vec::new();
        sqlite_varint(&mut cell, rec.len() as u64);
        sqlite_varint(&mut cell, rowid as u64 + 1);
        cell.extend_from_slice(rec);
        content -= cell.len();
        page[content..content + cell.len()].copy_from_slice(&cell);
        ptrs.push(content as u16);
    }
    page[hdr] = 0x0D;
    page[hdr + 3..hdr + 5].copy_from_slice(&(records.len() as u16).to_be_bytes());
    page[hdr + 5..hdr + 7].copy_from_slice(&(content as u16).to_be_bytes());
    for (i, p) in ptrs.iter().enumerate() {
        page[hdr + 8 + i * 2..hdr + 10 + i * 2].copy_from_slice(&p.to_be_bytes());
    }
    page
}

/// SQLite database (4 KiB pages) with `(name, sql)` tables in the schema and `rows` spread over
/// `data_pages` extra leaf pages.
pub fn sqlite(tables: &[(&str, &str)], rows: &[&[u8]], data_pages: usize) -> Vec<u8> {
    const PS: usize = 4096;
    let schema: Vec<Vec<u8>> = tables
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| {
            sqlite_record(&[b"table", name.as_bytes(), name.as_bytes(), b"", sql.as_bytes()], Some(i as u8 + 2))
        })
        .collect();
    let mut db = sqlite_leaf(PS, 100, &schema);
    db[..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(PS as u16).to_be_bytes());
    db[18] = 1;
    db[19] = 1;
    db[21] = 64;
    db[22] = 32;
    db[23] = 32;
    db[24..28].copy_from_slice(&1u32.to_be_bytes());
    db[28..32].copy_from_slice(&(1 + data_pages as u32).to_be_bytes());
    db[44..48].copy_from_slice(&4u32.to_be_bytes());
    db[56..60].copy_from_slice(&1u32.to_be_bytes());
    db[92..96].copy_from_slice(&1u32.to_be_bytes());
    for p in 0..data_pages {
        let mut recs: Vec<Vec<u8>> =
            rows.iter().skip(p).step_by(data_pages.max(1)).map(|r| sqlite_record(&[r], None)).collect();
        let filler = lorem(300);
        while recs.len() < 6 {
            recs.push(sqlite_record(&[&filler], None));
        }
        db.extend_from_slice(&sqlite_leaf(PS, 0, &recs));
    }
    db
}

/// Bitcoin Core-like Berkeley DB btree file with wallet records.
pub fn bdb_wallet(pages: usize) -> Vec<u8> {
    const PS: usize = 4096;
    let mut db = vec![0u8; PS * pages];
    db[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
    db[16..20].copy_from_slice(&9u32.to_le_bytes());
    db[20..24].copy_from_slice(&(PS as u32).to_le_bytes());
    db[25] = 9;
    db[32..36].copy_from_slice(&(pages as u32 - 1).to_le_bytes());
    let records: [&[u8]; 4] = [b"\x04mkey", b"\x04ckey", b"\x04name", b"\x0aminversion"];
    for i in 1..pages {
        let page = &mut db[i * PS..(i + 1) * PS];
        page[8..12].copy_from_slice(&(i as u32).to_le_bytes());
        page[25] = 5;
        let body = random(PS - 200, i as u64);
        page[100..PS - 100].copy_from_slice(&body);
        let rec = records[i % records.len()];
        page[40..40 + rec.len()].copy_from_slice(rec);
    }
    db
}

pub fn gzip(name: &str, data: &[u8]) -> Vec<u8> {
    let mut e = flate2::GzBuilder::new().filename(name).write(Vec::new(), Compression::default());
    e.write_all(data).expect("in-memory write");
    e.finish().expect("in-memory finish")
}

/// ustar archive.
pub fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// RAR 4 archive with stored members.
pub fn rar4(members: &[(&str, &[u8])]) -> Vec<u8> {
    fn block(out: &mut Vec<u8>, kind: u8, flags: u16, body: &[u8]) {
        let mut h = vec![kind];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&((body.len() + 7) as u16).to_le_bytes());
        h.extend_from_slice(body);
        let crc = (crc32fast::hash(&h) & 0xFFFF) as u16;
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&h);
    }
    let mut out = b"Rar!\x1A\x07\x00".to_vec();
    block(&mut out, 0x73, 0, &[0; 6]);
    for (name, data) in members {
        let mut b = Vec::new();
        for v in [data.len() as u32, data.len() as u32] {
            le32(&mut b, v);
        }
        b.push(2);
        le32(&mut b, crc32fast::hash(data));
        le32(&mut b, 0);
        b.extend_from_slice(&[29, 0x30]);
        le16(&mut b, name.len() as u16);
        le32(&mut b, 0x20);
        b.extend_from_slice(name.as_bytes());
        block(&mut out, 0x74, 0x8000, &b);
        out.extend_from_slice(data);
    }
    block(&mut out, 0x7B, 0x4000, &[]);
    out
}

pub fn electrum_json() -> Vec<u8> {
    br#"{
    "addr_history": {},
    "keystore": {"type": "bip32", "xpub": "xpub661MyMwAqRbcF", "xprv": null},
    "seed_version": 18,
    "use_encryption": false,
    "wallet_type": "standard"
}"#
    .to_vec()
}
