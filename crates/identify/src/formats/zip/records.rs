//! On-disk ZIP records. Every parser takes the whole buffer plus a position and never panics.

use strata_kernel::bytes::{u16_le, u32_le, u64_le};

pub const LOCAL_SIG: &[u8] = b"PK\x03\x04";
pub const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
pub const EOCD_SIG: &[u8] = b"PK\x05\x06";
pub const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
pub const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
pub const DESCRIPTOR_SIG: &[u8] = b"PK\x07\x08";

const KNOWN_METHODS: &[u16] = &[0, 1, 6, 8, 9, 12, 14, 19, 93, 95, 96, 97, 98, 99];

fn sig_at(data: &[u8], pos: usize, sig: &[u8]) -> bool {
    data.get(pos..pos.saturating_add(sig.len())) == Some(sig)
}

fn plausible_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.iter().any(|b| *b == 0 || (*b < 0x20 && *b != b'\t'))
}

/// Decode a member name: UTF-8 when flagged or valid, otherwise CP437-ish lossy.
pub fn decode_name(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|b| if b.is_ascii() { char::from(*b) } else { '\u{FFFD}' }).collect(),
    }
}

#[derive(Debug, Clone)]
pub struct LocalHeader {
    pub pos: usize,
    pub flags: u16,
    pub method: u16,
    pub dos_time: u32,
    pub crc32: u32,
    pub compressed: u64,
    pub uncompressed: u64,
    pub name: String,
    pub data_start: usize,
}

impl LocalHeader {
    pub fn parse(data: &[u8], pos: usize) -> Option<Self> {
        if !sig_at(data, pos, LOCAL_SIG) {
            return None;
        }
        let version = u16_le(data, pos + 4)?;
        let method = u16_le(data, pos + 8)?;
        let name_len = usize::from(u16_le(data, pos + 26)?);
        let extra_len = usize::from(u16_le(data, pos + 28)?);
        if version > 100 || !KNOWN_METHODS.contains(&method) || name_len == 0 || name_len > 1024 {
            return None;
        }
        let name_start = pos + 30;
        let raw_name = data.get(name_start..name_start + name_len)?;
        if !plausible_name(raw_name) {
            return None;
        }
        let extra = data.get(name_start + name_len..name_start + name_len + extra_len).unwrap_or_default();
        let mut compressed = u64::from(u32_le(data, pos + 18)?);
        let mut uncompressed = u64::from(u32_le(data, pos + 22)?);
        if let Some(z) = Zip64Extra::find(extra) {
            let mut values = z.values();
            if uncompressed == 0xFFFF_FFFF {
                uncompressed = values.next().unwrap_or(uncompressed);
            }
            if compressed == 0xFFFF_FFFF {
                compressed = values.next().unwrap_or(compressed);
            }
        }
        Some(Self {
            pos,
            flags: u16_le(data, pos + 6)?,
            method,
            dos_time: u32_le(data, pos + 10)?,
            crc32: u32_le(data, pos + 14)?,
            compressed,
            uncompressed,
            name: decode_name(raw_name),
            data_start: name_start + name_len + extra_len,
        })
    }

    pub fn has_descriptor(&self) -> bool {
        self.flags & 0x0008 != 0
    }
}

#[derive(Debug, Clone)]
pub struct CentralHeader {
    pub flags: u16,
    pub method: u16,
    pub dos_time: u32,
    pub crc32: u32,
    pub compressed: u64,
    pub uncompressed: u64,
    pub local_offset: u64,
    pub name: String,
    pub next: usize,
}

impl CentralHeader {
    pub fn parse(data: &[u8], pos: usize) -> Option<Self> {
        if !sig_at(data, pos, CENTRAL_SIG) {
            return None;
        }
        let method = u16_le(data, pos + 10)?;
        let name_len = usize::from(u16_le(data, pos + 28)?);
        let extra_len = usize::from(u16_le(data, pos + 30)?);
        let comment_len = usize::from(u16_le(data, pos + 32)?);
        if !KNOWN_METHODS.contains(&method) || name_len == 0 || name_len > 1024 {
            return None;
        }
        let name_start = pos + 46;
        let raw_name = data.get(name_start..name_start + name_len)?;
        if !plausible_name(raw_name) {
            return None;
        }
        let extra = data.get(name_start + name_len..name_start + name_len + extra_len).unwrap_or_default();
        let mut compressed = u64::from(u32_le(data, pos + 20)?);
        let mut uncompressed = u64::from(u32_le(data, pos + 24)?);
        let mut local_offset = u64::from(u32_le(data, pos + 42)?);
        if let Some(z) = Zip64Extra::find(extra) {
            let mut values = z.values();
            for field in [&mut uncompressed, &mut compressed, &mut local_offset] {
                if *field == 0xFFFF_FFFF {
                    *field = values.next().unwrap_or(*field);
                }
            }
        }
        Some(Self {
            flags: u16_le(data, pos + 8)?,
            method,
            dos_time: u32_le(data, pos + 12)?,
            crc32: u32_le(data, pos + 16)?,
            compressed,
            uncompressed,
            local_offset,
            name: decode_name(raw_name),
            next: name_start + name_len + extra_len + comment_len,
        })
    }
}

/// End of central directory, merged with the ZIP64 record when present.
#[derive(Debug, Clone)]
pub struct Eocd {
    pub pos: usize,
    pub entries: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
    /// Position just after the record and its comment.
    pub end: usize,
    pub zip64: bool,
    /// Position of the first end record (ZIP64 EOCD when present).
    pub record_start: usize,
}

impl Eocd {
    pub fn parse(data: &[u8], pos: usize) -> Option<Self> {
        if !sig_at(data, pos, EOCD_SIG) {
            return None;
        }
        let comment = usize::from(u16_le(data, pos + 20)?);
        let mut e = Self {
            pos,
            entries: u64::from(u16_le(data, pos + 10)?),
            cd_size: u64::from(u32_le(data, pos + 12)?),
            cd_offset: u64::from(u32_le(data, pos + 16)?),
            end: (pos + 22 + comment).min(data.len()),
            zip64: false,
            record_start: pos,
        };
        if let Some(loc) = pos.checked_sub(20).filter(|l| sig_at(data, *l, ZIP64_LOCATOR_SIG)) {
            e.apply_zip64(data, loc);
        }
        Some(e)
    }

    fn apply_zip64(&mut self, data: &[u8], locator: usize) {
        // The locator's absolute offset may be shifted; the record normally sits right before it.
        let candidates = [locator.checked_sub(56), u64_le(data, locator + 8).and_then(|o| usize::try_from(o).ok())];
        for pos in candidates.into_iter().flatten() {
            if !sig_at(data, pos, ZIP64_EOCD_SIG) {
                continue;
            }
            if let (Some(n), Some(size), Some(off)) =
                (u64_le(data, pos + 32), u64_le(data, pos + 40), u64_le(data, pos + 48))
            {
                self.entries = n;
                self.cd_size = size;
                self.cd_offset = off;
                self.zip64 = true;
                self.record_start = pos;
                return;
            }
        }
    }
}

/// ZIP64 extended information extra field (header id 0x0001).
struct Zip64Extra<'a>(&'a [u8]);

impl<'a> Zip64Extra<'a> {
    fn find(extra: &'a [u8]) -> Option<Self> {
        let mut pos = 0;
        while let (Some(id), Some(len)) = (u16_le(extra, pos), u16_le(extra, pos + 2)) {
            let body = extra.get(pos + 4..pos + 4 + usize::from(len))?;
            if id == 1 {
                return Some(Self(body));
            }
            pos += 4 + usize::from(len);
        }
        None
    }

    fn values(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c))
    }
}
