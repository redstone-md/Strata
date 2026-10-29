//! Builders for images, documents and executables.

use super::{le16, le32, lorem, random};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32fast::hash(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// RGB PNG of noise (so IDAT is large and incompressible).
pub fn png(w: u32, h: u32) -> Vec<u8> {
    let mut out = b"\x89PNG\r\n\x1A\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_chunk(&mut out, b"IHDR", &ihdr);
    let mut raw = Vec::new();
    for y in 0..h {
        raw.push(0);
        raw.extend_from_slice(&random(w as usize * 3, u64::from(y) + 7));
    }
    let mut z = ZlibEncoder::new(Vec::new(), Compression::fast());
    z.write_all(&raw).expect("in-memory write");
    let idat = z.finish().expect("in-memory finish");
    for part in idat.chunks(8192) {
        png_chunk(&mut out, b"IDAT", part);
    }
    png_chunk(&mut out, b"IEND", &[]);
    out
}

/// Baseline JPEG skeleton: JFIF, DQT, SOF0, DHT, SOS, `scan_len` bytes of byte-stuffed
/// entropy data, EOI.
pub fn jpeg(scan_len: usize) -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8];
    out.extend_from_slice(&[0xFF, 0xE0, 0, 16]);
    out.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    out.extend_from_slice(&[0xFF, 0xDB, 0, 67, 0]);
    out.extend((1..=64u8).map(|q| q % 50 + 1));
    out.extend_from_slice(&[0xFF, 0xC0, 0, 17, 8, 0x01, 0xE0, 0x02, 0x80, 3]);
    for id in 1..=3u8 {
        out.extend_from_slice(&[id, 0x11, 0]);
    }
    out.extend_from_slice(&[0xFF, 0xC4, 0, 31, 0x00, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]);
    out.extend(0..12u8);
    out.extend_from_slice(&[0xFF, 0xDA, 0, 12, 3, 1, 0, 2, 0, 3, 0, 0, 63, 0]);
    for b in random(scan_len, 99) {
        out.push(b);
        if b == 0xFF {
            out.push(0);
        }
    }
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

/// PDF with `objects` objects (every third one a stream) and a trailer.
pub fn pdf(objects: usize) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    for i in 1..=objects {
        if i % 3 == 0 {
            let body = lorem(200);
            out.extend_from_slice(format!("{i} 0 obj\n<< /Length {} >>\nstream\n", body.len()).as_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(b"\nendstream\nendobj\n");
        } else {
            out.extend_from_slice(format!("{i} 0 obj\n<< /Type /Page /Parent 2 0 R /Title (page {i}) >>\nendobj\n").as_bytes());
        }
    }
    let tail = format!("xref\n0 {n}\ntrailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n9\n%%EOF\n", n = objects + 1);
    out.extend_from_slice(tail.as_bytes());
    out
}

/// OLE2 v3 compound file with the given streams (each `stream_len` bytes, >= 4096).
pub fn ole(streams: &[&str], stream_len: usize) -> Vec<u8> {
    const SS: usize = 512;
    const FREE: u32 = 0xFFFF_FFFF;
    const END: u32 = 0xFFFF_FFFE;
    let sectors_per_stream = stream_len.div_ceil(SS);
    let mut fat = vec![FREE; SS / 4];
    fat[0] = 0xFFFF_FFFD;
    fat[1] = END;
    let mut next = 2usize;
    let mut starts = Vec::new();
    for _ in streams {
        starts.push(next as u32);
        for k in 0..sectors_per_stream {
            fat[next + k] = if k + 1 == sectors_per_stream { END } else { (next + k + 1) as u32 };
        }
        next += sectors_per_stream;
    }
    let mut out = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
    out.extend_from_slice(&[0u8; 16]);
    for v in [0x3Eu16, 3, 0xFFFE, 9, 6, 0, 0, 0] {
        le16(&mut out, v);
    }
    for v in [0u32, 1, 1, 0, 4096, END, 0, END, 0] {
        le32(&mut out, v);
    }
    le32(&mut out, 0);
    while out.len() < SS {
        le32(&mut out, FREE);
    }
    for v in &fat {
        le32(&mut out, *v);
    }
    let mut dir = Vec::new();
    let names: Vec<&str> = std::iter::once("Root Entry").chain(streams.iter().copied()).collect();
    for (i, name) in names.iter().enumerate() {
        let mut e = [0u8; 128];
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        e[..units.len()].copy_from_slice(&units);
        e[64..66].copy_from_slice(&((units.len() + 2) as u16).to_le_bytes());
        e[66] = if i == 0 { 5 } else { 2 };
        e[67] = 1;
        let right = if i > 0 && i + 1 < names.len() { (i + 1) as u32 } else { FREE };
        e[68..72].copy_from_slice(&FREE.to_le_bytes());
        e[72..76].copy_from_slice(&right.to_le_bytes());
        let child = if i == 0 && names.len() > 1 { 1 } else { FREE };
        e[76..80].copy_from_slice(&child.to_le_bytes());
        let (start, size) = if i == 0 { (END, 0) } else { (starts[i - 1], stream_len as u64) };
        e[116..120].copy_from_slice(&start.to_le_bytes());
        e[120..128].copy_from_slice(&size.to_le_bytes());
        dir.extend_from_slice(&e);
    }
    dir.resize(SS, 0);
    out.extend_from_slice(&dir);
    for i in 0..streams.len() {
        out.extend_from_slice(&random(sectors_per_stream * SS, i as u64 + 3));
    }
    out
}

/// Minimal x64 PE: two sections; `dll` sets IMAGE_FILE_DLL.
pub fn pe(dll: bool) -> Vec<u8> {
    let mut out = vec![0u8; 0x800];
    out[..2].copy_from_slice(b"MZ");
    out[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    out[0x4E..0x4E + 39].copy_from_slice(b"This program cannot be run in DOS mode.");
    let pe = 0x80;
    out[pe..pe + 4].copy_from_slice(b"PE\0\0");
    out[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    out[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
    out[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
    let ch: u16 = if dll { 0x2022 } else { 0x0022 };
    out[pe + 22..pe + 24].copy_from_slice(&ch.to_le_bytes());
    let opt = pe + 24;
    out[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    out[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
    let table = opt + 240;
    for (i, (name, ptr)) in [(&b".text"[..], 0x400u32), (b".data", 0x600)].iter().enumerate() {
        let s = table + i * 40;
        out[s..s + name.len()].copy_from_slice(name);
        out[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        out[s + 20..s + 24].copy_from_slice(&ptr.to_le_bytes());
    }
    out[0x400..0x800].copy_from_slice(&random(0x400, 5));
    out
}
