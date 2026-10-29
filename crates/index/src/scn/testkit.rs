//! Writer for synthetic scan files with the decoded structure (tests only; no real data).

/// Builds a scan file group by group.
pub struct ScnWriter {
    body: Vec<u8>,
}

impl Default for ScnWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScnWriter {
    pub fn new() -> Self {
        Self { body: Vec::new() }
    }

    fn group(&mut self, tag: [u8; 4], sub: [u8; 4], payload: &[u8]) {
        self.body.extend_from_slice(&(payload.len() as u32 + 16).to_le_bytes());
        self.body.extend_from_slice(&tag);
        self.body.extend_from_slice(&sub);
        self.body.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
        self.body.extend_from_slice(payload);
    }

    /// An object group; `scanned` marks the device the scan ran on.
    pub fn object(&mut self, payload: &[u8], scanned: bool) {
        self.group(if scanned { *b"ESNI" } else { *b"TONI" }, [0; 4], payload);
    }

    pub fn progress(&mut self, scanned: u64) {
        let mut p = 0u64.to_le_bytes().to_vec();
        p.extend_from_slice(&scanned.to_le_bytes());
        self.group(*b"OOGR", [0; 4], &p);
    }

    pub fn element(&mut self, kind: u16, tag: [u8; 2], payload: &[u8]) {
        let k = kind.to_le_bytes();
        self.group(*b"HS\0\0", [k[0], k[1], tag[0], tag[1]], payload);
    }

    /// File-type entries as one stream split into groups every `split` bytes (entries cross
    /// group boundaries, as in real files).
    pub fn file_types(&mut self, entries: &[FileTypeEntry], split: usize) {
        let stream: Vec<u8> = entries.iter().flat_map(FileTypeEntry::encode).collect();
        for piece in stream.chunks(split.max(1)) {
            self.element(4, *b"TF", piece);
        }
    }

    pub fn finish(self) -> Vec<u8> {
        let mut out: Vec<u8> = (0..0x70u32).map(|i| (i * 7 + 3) as u8).collect();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.resize(0x80, 0);
        out.extend(self.body);
        out
    }
}

/// Property records of one object.
pub struct ObjectBuilder {
    id: u32,
    records: Vec<u8>,
}

impl ObjectBuilder {
    pub fn new(id: u32) -> Self {
        Self { id, records: Vec::new() }.prop(b"DRVA", 0x02, &id.to_le_bytes())
    }

    /// Append a property; `class` is given readable and stored backwards.
    pub fn prop(mut self, class: &[u8; 4], prop: u32, value: &[u8]) -> Self {
        self.records.extend_from_slice(&self.id.to_le_bytes());
        self.records.extend_from_slice(&prop.to_le_bytes());
        self.records.extend_from_slice(&[class[3], class[2], class[1], class[0]]);
        self.records.extend_from_slice(&0u32.to_le_bytes());
        self.records.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.records.extend_from_slice(value);
        self
    }

    pub fn parent(self, parent: u32) -> Self {
        self.prop(b"DRVA", 0x10, &parent.to_le_bytes())
    }

    pub fn partition(self, start: u64, size: u64, kind: u32) -> Self {
        self.prop(b"PART", 0x02, &start.to_le_bytes()).prop(b"PART", 0x01, &size.to_le_bytes()).prop(b"PART", 0x201, &kind.to_le_bytes())
    }

    pub fn disk(self, size: u64, sector: u32) -> Self {
        self.prop(b"SIZE", 0x01, &size.to_le_bytes()).prop(b"SIZE", 0x02, &sector.to_le_bytes())
    }

    pub fn fs_name(self, name: &str) -> Self {
        self.prop(b"RCFS", 0x01, &utf16z(name))
    }

    pub fn name(self, name: &str) -> Self {
        self.prop(b"BASE", 0x20, &utf16z(name))
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.records.extend_from_slice(&self.id.to_le_bytes());
        self.records.extend_from_slice(&[0; 12]);
        self.records.extend_from_slice(&u32::MAX.to_le_bytes());
        self.records
    }
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// One NTFS boot element record.
pub fn ntfs_record(at: u64, volume_size: u64, sector: u32) -> Vec<u8> {
    let mut r = Vec::with_capacity(48);
    r.extend_from_slice(&4096u32.to_le_bytes());
    r.extend_from_slice(&1024u32.to_le_bytes());
    r.extend_from_slice(&0xC000_0000u64.to_le_bytes());
    r.extend_from_slice(&0x2000u64.to_le_bytes());
    r.extend_from_slice(&4096u32.to_le_bytes());
    r.extend_from_slice(&sector.to_le_bytes());
    r.extend_from_slice(&volume_size.to_le_bytes());
    r.extend_from_slice(&at.to_le_bytes());
    r
}

/// One FAT boot element record.
pub fn fat_record(fat_bits: u32, at: u64) -> Vec<u8> {
    let mut r = vec![0u8; 80];
    r[..4].copy_from_slice(&fat_bits.to_le_bytes());
    r[52..56].copy_from_slice(&512u32.to_le_bytes());
    r[72..80].copy_from_slice(&at.to_le_bytes());
    r
}

/// One file-type stream entry.
#[derive(Debug, Clone)]
pub struct FileTypeEntry {
    sector: u64,
    size: u64,
    tag: [u8; 4],
    details: Option<(u8, Option<String>)>,
}

impl FileTypeEntry {
    /// `tag` readable, e.g. `*b"\0JPG"`.
    pub fn new(sector: u64, size: u64, tag: [u8; 4]) -> Self {
        Self { sector, size, tag, details: None }
    }

    /// Details with `mask`; the string is used when bit 0x10 is set.
    pub fn details(mut self, mask: u8, text: Option<&str>) -> Self {
        self.details = Some((mask, text.map(str::to_string)));
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let width = |v: u64, widths: [usize; 4]| widths.iter().position(|w| *w == 8 || v < 1u64 << (8 * w)).unwrap_or(3);
        let sw = width(self.sector, [3, 4, 5, 8]);
        let zw = width(self.size, [2, 3, 4, 8]);
        let mut out = vec![0x60 | sw as u8 | (zw as u8) << 2 | if self.details.is_some() { 0x80 } else { 0 }, 0x06];
        out.extend_from_slice(&self.sector.to_le_bytes()[..[3, 4, 5, 8][sw]]);
        out.extend_from_slice(&self.size.to_le_bytes()[..[2, 3, 4, 8][zw]]);
        out.extend_from_slice(&[self.tag[3], self.tag[2], self.tag[1], self.tag[0]]);
        out.extend_from_slice(&0x1234u16.to_le_bytes());
        if let Some((mask, text)) = &self.details {
            out.push(*mask);
            for (bit, len) in [(0x01u8, 4usize), (0x02, 6), (0x04, 2), (0x08, 8)] {
                if mask & bit != 0 {
                    out.extend(std::iter::repeat_n(0x11, len));
                }
            }
            if mask & 0x10 != 0 {
                let t = text.clone().unwrap_or_default();
                out.push(t.len() as u8 + 1);
                out.push(0x05);
                out.extend_from_slice(t.as_bytes());
            }
        }
        out
    }
}
