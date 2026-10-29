//! Hand-built EVTX chunks for tests: a BinXML writer with inline names and template
//! definitions, record framing, chunk and file headers with valid checksums.

use super::chunk::{CHUNK_SIG, CHUNK_SIZE};

/// 2011-05-14 17:36:09 UTC.
pub(crate) const FT: u64 = 129_498_681_690_000_000;

pub(crate) enum Val {
    Raw(u8, Vec<u8>),
    Xml(Box<dyn FnOnce(&mut Xml<'_>)>),
}

pub(crate) fn s(v: &str) -> Val {
    Val::Raw(0x01, v.encode_utf16().flat_map(u16::to_le_bytes).collect())
}

pub(crate) fn u16v(v: u16) -> Val {
    Val::Raw(0x06, v.to_le_bytes().to_vec())
}

pub(crate) fn ft(v: u64) -> Val {
    Val::Raw(0x11, v.to_le_bytes().to_vec())
}

/// Appends BinXML tokens to a chunk buffer (offsets are chunk-relative).
pub(crate) struct Xml<'b> {
    buf: &'b mut Vec<u8>,
}

impl Xml<'_> {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn wide(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.u16(units.len() as u16);
        for u in units {
            self.u16(u);
        }
    }

    /// Name reference followed by the name itself (inline).
    fn name(&mut self, name: &str) {
        let at = self.buf.len() as u32 + 4;
        self.u32(at);
        self.u32(0);
        self.u16(0);
        self.wide(name);
        self.u16(0);
    }

    pub(crate) fn fragment(&mut self) {
        self.buf.extend_from_slice(&[0x0F, 1, 1, 0]);
    }

    pub(crate) fn open(&mut self, name: &str, attrs: bool) {
        self.buf.push(if attrs { 0x41 } else { 0x01 });
        self.u16(0xFFFF);
        self.u32(0);
        self.name(name);
        if attrs {
            self.u32(0);
        }
    }

    pub(crate) fn attr(&mut self, name: &str) {
        self.buf.push(0x06);
        self.name(name);
    }

    pub(crate) fn text(&mut self, text: &str) {
        self.buf.extend_from_slice(&[0x05, 0x01]);
        self.wide(text);
    }

    pub(crate) fn sub(&mut self, id: u16, ty: u8, optional: bool) {
        self.buf.push(if optional { 0x0E } else { 0x0D });
        self.u16(id);
        self.buf.push(ty);
    }

    pub(crate) fn close_start(&mut self) {
        self.buf.push(0x02);
    }

    pub(crate) fn close_empty(&mut self) {
        self.buf.push(0x03);
    }

    pub(crate) fn end(&mut self) {
        self.buf.push(0x04);
    }

    pub(crate) fn eof(&mut self) {
        self.buf.push(0x00);
    }

    /// `<name>text</name>` with optional `Name="…"` attribute (EventData style).
    pub(crate) fn data(&mut self, attr_name: Option<&str>, text: &str) {
        self.open("Data", attr_name.is_some());
        if let Some(n) = attr_name {
            self.attr("Name");
            self.text(n);
        }
        self.close_start();
        self.text(text);
        self.end();
    }

    /// Template instance. With `def` the definition is written inline (and its offset returned
    /// for reuse); otherwise `shared` names an earlier definition.
    pub(crate) fn template(&mut self, def: Option<&dyn Fn(&mut Xml<'_>)>, shared: u32, values: Vec<Val>) -> u32 {
        self.buf.extend_from_slice(&[0x0C, 0x01]);
        self.u32(7);
        let def_off = match def {
            Some(body) => {
                let off = self.buf.len() as u32 + 4;
                self.u32(off);
                self.u32(0);
                self.buf.extend_from_slice(&[0xAB; 16]);
                let size_at = self.buf.len();
                self.u32(0);
                let start = self.buf.len();
                body(self);
                let size = (self.buf.len() - start) as u32;
                self.buf[size_at..size_at + 4].copy_from_slice(&size.to_le_bytes());
                off
            }
            None => {
                self.u32(shared);
                shared
            }
        };
        self.u32(values.len() as u32);
        let desc_at = self.buf.len();
        for _ in &values {
            self.u32(0);
        }
        for (i, v) in values.into_iter().enumerate() {
            let start = self.buf.len();
            let ty = match v {
                Val::Raw(ty, bytes) => {
                    self.buf.extend_from_slice(&bytes);
                    ty
                }
                Val::Xml(body) => {
                    body(self);
                    0x21
                }
            };
            let size = (self.buf.len() - start) as u16;
            let d = desc_at + 4 * i;
            self.buf[d..d + 2].copy_from_slice(&size.to_le_bytes());
            self.buf[d + 2] = ty;
        }
        def_off
    }
}

/// One chunk being written.
pub(crate) struct ChunkBuilder {
    buf: Vec<u8>,
    ids: Vec<u64>,
    last: usize,
}

impl Default for ChunkBuilder {
    fn default() -> Self {
        let mut buf = vec![0u8; 0x200];
        buf[..8].copy_from_slice(CHUNK_SIG);
        Self { buf, ids: Vec::new(), last: 0 }
    }
}

impl ChunkBuilder {
    /// Append a record; `body` writes its BinXML (fragment header included). Returns whatever
    /// `body` returns (e.g. a template offset).
    pub(crate) fn record<R>(&mut self, id: u64, written: u64, body: impl FnOnce(&mut Xml<'_>) -> R) -> R {
        let start = self.buf.len();
        self.last = start;
        self.buf.extend_from_slice(b"\x2a\x2a\x00\x00");
        self.buf.extend_from_slice(&[0; 4]);
        self.buf.extend_from_slice(&id.to_le_bytes());
        self.buf.extend_from_slice(&written.to_le_bytes());
        let out = body(&mut Xml { buf: &mut self.buf });
        self.buf.resize((self.buf.len() + 4).div_ceil(8) * 8 - 4, 0);
        let size = (self.buf.len() + 4 - start) as u32;
        self.buf.extend_from_slice(&size.to_le_bytes());
        self.buf[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
        self.ids.push(id);
        out
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        let first = self.ids.first().copied().unwrap_or(0);
        let last = self.ids.last().copied().unwrap_or(0);
        let free = self.buf.len() as u32;
        for (at, v) in [(8, first), (16, last), (24, first), (32, last)] {
            self.buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        self.buf[40..44].copy_from_slice(&0x80u32.to_le_bytes());
        self.buf[44..48].copy_from_slice(&(self.last as u32).to_le_bytes());
        self.buf[48..52].copy_from_slice(&free.to_le_bytes());
        let records = crc32fast::hash(&self.buf[0x200..]);
        self.buf[52..56].copy_from_slice(&records.to_le_bytes());
        let mut h = crc32fast::Hasher::new();
        h.update(&self.buf[..120]);
        h.update(&self.buf[128..0x200]);
        let header = h.finalize();
        self.buf[124..128].copy_from_slice(&header.to_le_bytes());
        self.buf.resize(CHUNK_SIZE, 0);
        self.buf
    }
}

/// File header (valid checksum) followed by the chunks.
pub(crate) fn evtx_file(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0u8; 0x1000];
    out[..8].copy_from_slice(b"ElfFile\0");
    out[16..24].copy_from_slice(&(chunks.len().saturating_sub(1) as u64).to_le_bytes());
    out[32..36].copy_from_slice(&0x80u32.to_le_bytes());
    out[36..38].copy_from_slice(&1u16.to_le_bytes());
    out[38..40].copy_from_slice(&3u16.to_le_bytes());
    out[40..42].copy_from_slice(&0x1000u16.to_le_bytes());
    out[42..44].copy_from_slice(&(chunks.len() as u16).to_le_bytes());
    let sum = crc32fast::hash(&out[..120]);
    out[124..128].copy_from_slice(&sum.to_le_bytes());
    for c in chunks {
        out.extend_from_slice(c);
    }
    out
}

/// The standard event template: System (Provider, EventID, TimeCreated, Computer, Channel) and
/// EventData as a nested BinXML value (substitution 5).
pub(crate) fn event_template(x: &mut Xml<'_>) {
    x.fragment();
    x.open("Event", false);
    x.close_start();
    x.open("System", false);
    x.close_start();
    x.open("Provider", true);
    x.attr("Name");
    x.sub(0, 0x01, false);
    x.close_empty();
    x.open("EventID", false);
    x.close_start();
    x.sub(1, 0x06, false);
    x.end();
    x.open("TimeCreated", true);
    x.attr("SystemTime");
    x.sub(2, 0x11, false);
    x.close_empty();
    x.open("Computer", false);
    x.close_start();
    x.sub(3, 0x01, false);
    x.end();
    x.open("Channel", false);
    x.close_start();
    x.sub(4, 0x01, true);
    x.end();
    x.end();
    x.open("EventData", false);
    x.close_start();
    x.sub(5, 0x21, true);
    x.end();
    x.end();
    x.eof();
}

/// Values for [`event_template`]; `data` becomes `<Data Name=…>` elements.
pub(crate) fn event_values(provider: &str, id: u16, time: u64, channel: &str, data: &[(&str, &str)]) -> Vec<Val> {
    let pairs: Vec<(String, String)> = data.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
    vec![
        s(provider),
        u16v(id),
        ft(time),
        s("ADMIN-PC"),
        s(channel),
        Val::Xml(Box::new(move |x: &mut Xml<'_>| {
            x.fragment();
            for (n, v) in &pairs {
                x.data((!n.is_empty()).then_some(n.as_str()), v);
            }
            x.eof();
        })),
    ]
}

/// A small Security + System log: logon (inline template), failed logon and a boot (shared).
pub(crate) fn sample_log() -> Vec<u8> {
    let mut c = ChunkBuilder::default();
    let sec = "Microsoft-Windows-Security-Auditing";
    let logon = [("TargetUserName", "Admin"), ("TargetDomainName", "ADMIN-PC"), ("LogonType", "2")];
    let tpl = c.record(1, FT, |x| {
        x.fragment();
        x.template(Some(&event_template), 0, event_values(sec, 4624, FT, "Security", &logon))
    });
    let failed = [("TargetUserName", "bitcoin"), ("LogonType", "10")];
    c.record(2, FT + 10_000_000, |x| {
        x.fragment();
        x.template(None, tpl, event_values(sec, 4625, FT + 10_000_000, "Security", &failed));
    });
    c.record(3, FT + 20_000_000, |x| {
        x.fragment();
        x.template(None, tpl, event_values("EventLog", 6005, FT + 20_000_000, "System", &[]));
    });
    evtx_file(&[c.finish()])
}
