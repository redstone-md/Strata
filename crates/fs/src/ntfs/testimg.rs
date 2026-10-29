//! Byte builders for tiny synthetic NTFS volumes.

use std::collections::BTreeSet;

pub(super) const CS: u64 = 4096;
pub(super) const RS: usize = 1024;
pub(super) const CLUSTERS: u64 = 256;
/// 2011-05-01 12:00:00 UTC.
pub(super) const FT: u64 = 129_487_248_000_000_000;

pub(super) fn fref(record: u64, seq: u16) -> u64 {
    record | (u64::from(seq) << 48)
}

/// Mapping pairs for `(absolute lcn or sparse, length)` runs.
pub(super) fn encode_runs(runs: &[(Option<i64>, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = 0i64;
    for &(lcn, len) in runs {
        let len_bytes = min_bytes_unsigned(len);
        let delta = lcn.map(|l| l - prev);
        let off_bytes = delta.map_or(0, min_bytes_signed);
        out.push((off_bytes << 4) as u8 | len_bytes as u8);
        out.extend_from_slice(&len.to_le_bytes()[..len_bytes]);
        if let (Some(d), Some(l)) = (delta, lcn) {
            out.extend_from_slice(&d.to_le_bytes()[..off_bytes]);
            prev = l;
        }
    }
    out.push(0);
    out
}

fn min_bytes_unsigned(v: u64) -> usize {
    (1..=8).find(|n| *n == 8 || v < 1u64 << (8 * n)).unwrap_or(8)
}

fn min_bytes_signed(v: i64) -> usize {
    (1..=8).find(|n| *n == 8 || (-(1i64 << (8 * n - 1))..(1i64 << (8 * n - 1))).contains(&v)).unwrap_or(8)
}

fn pad8(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(8) {
        v.push(0);
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub(super) struct RecordBuilder {
    number: u64,
    seq: u16,
    flags: u16,
    base: u64,
    attrs: Vec<Vec<u8>>,
}

impl RecordBuilder {
    pub(super) fn new(number: u64, seq: u16) -> Self {
        Self { number, seq, flags: 1, base: 0, attrs: Vec::new() }
    }

    pub(super) fn deleted(mut self) -> Self {
        self.flags &= !1;
        self
    }

    pub(super) fn dir(mut self) -> Self {
        self.flags |= 2;
        self
    }

    pub(super) fn base(mut self, base: u64) -> Self {
        self.base = base;
        self
    }

    pub(super) fn std_info(self) -> Self {
        let v: Vec<u8> = [FT; 4].iter().flat_map(|t| t.to_le_bytes()).chain([0u8; 16]).collect();
        self.resident(0x10, "", &v)
    }

    pub(super) fn file_name(self, parent: u64, name: &str, namespace: u8) -> Self {
        let mut v = parent.to_le_bytes().to_vec();
        for _ in 0..4 {
            v.extend_from_slice(&(FT + 10_000_000).to_le_bytes());
        }
        v.extend_from_slice(&[0u8; 16]);
        let dir = if self.flags & 2 != 0 { 0x1000_0000u32 } else { 0 };
        v.extend_from_slice(&dir.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]);
        v.push(name.encode_utf16().count() as u8);
        v.push(namespace);
        v.extend_from_slice(&utf16(name));
        self.resident(0x30, "", &v)
    }

    pub(super) fn resident(mut self, type_code: u32, name: &str, value: &[u8]) -> Self {
        let name = utf16(name);
        let value_off = (0x18 + name.len()).div_ceil(8) * 8;
        let mut a = vec![0u8; value_off];
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[9] = (name.len() / 2) as u8;
        a[0x0A..0x0C].copy_from_slice(&0x18u16.to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&(value_off as u16).to_le_bytes());
        a[0x18..0x18 + name.len()].copy_from_slice(&name);
        a.extend_from_slice(value);
        self.push_attr(a);
        self
    }

    pub(super) fn non_resident(self, type_code: u32, name: &str, start_vcn: u64, runs: &[(Option<i64>, u64)], size: u64) -> Self {
        self.non_resident_flags(type_code, name, start_vcn, runs, size, 0, 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn non_resident_flags(
        mut self,
        type_code: u32,
        name: &str,
        start_vcn: u64,
        runs: &[(Option<i64>, u64)],
        size: u64,
        flags: u16,
        unit: u8,
    ) -> Self {
        let name = utf16(name);
        let runs_off = (0x40 + name.len()).div_ceil(8) * 8;
        let mut a = vec![0u8; runs_off];
        let clusters: u64 = runs.iter().map(|r| r.1).sum();
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[8] = 1;
        a[9] = (name.len() / 2) as u8;
        a[0x0A..0x0C].copy_from_slice(&0x40u16.to_le_bytes());
        a[0x0C..0x0E].copy_from_slice(&flags.to_le_bytes());
        a[0x10..0x18].copy_from_slice(&start_vcn.to_le_bytes());
        a[0x18..0x20].copy_from_slice(&(start_vcn + clusters).saturating_sub(1).to_le_bytes());
        a[0x20..0x22].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[0x22] = unit;
        a[0x28..0x30].copy_from_slice(&(clusters * CS).to_le_bytes());
        a[0x30..0x38].copy_from_slice(&size.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&size.to_le_bytes());
        a[0x40..0x40 + name.len()].copy_from_slice(&name);
        a.extend_from_slice(&encode_runs(runs));
        self.push_attr(a);
        self
    }

    fn push_attr(&mut self, mut a: Vec<u8>) {
        pad8(&mut a);
        let len = a.len() as u32;
        a[4..8].copy_from_slice(&len.to_le_bytes());
        a[0x0E..0x10].copy_from_slice(&(self.attrs.len() as u16).to_le_bytes());
        self.attrs.push(a);
    }

    /// Record bytes with the update sequence applied (as on disk).
    pub(super) fn build(self) -> Vec<u8> {
        let mut r = vec![0u8; RS];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[0x10..0x12].copy_from_slice(&self.seq.to_le_bytes());
        r[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        r[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        r[0x16..0x18].copy_from_slice(&self.flags.to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&(RS as u32).to_le_bytes());
        r[0x20..0x28].copy_from_slice(&self.base.to_le_bytes());
        r[0x2C..0x30].copy_from_slice(&(self.number as u32).to_le_bytes());
        let mut off = 0x38;
        for a in &self.attrs {
            r[off..off + a.len()].copy_from_slice(a);
            off += a.len();
        }
        r[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        r[0x18..0x1C].copy_from_slice(&((off + 8) as u32).to_le_bytes());
        let usn = [0x07, 0x00];
        r[0x30..0x32].copy_from_slice(&usn);
        for i in 1..3 {
            let end = i * 512 - 2;
            let (orig0, orig1) = (r[end], r[end + 1]);
            r[0x30 + 2 * i] = orig0;
            r[0x30 + 2 * i + 1] = orig1;
            r[end..end + 2].copy_from_slice(&usn);
        }
        r
    }
}

/// `$MFT` in two fragments: records 0..16 at LCN 4, 16..32 at LCN 20.
pub(super) const MFT_RUNS: [(u64, u64); 2] = [(4, 4), (20, 4)];

/// A 1 MiB volume: 4 KiB clusters, 1 KiB records, fragmented `$MFT`.
pub(super) struct NtfsImage {
    bytes: Vec<u8>,
    used: BTreeSet<u64>,
    bitmap: bool,
}

impl NtfsImage {
    pub(super) fn new() -> Self {
        let mut bytes = vec![0u8; (CLUSTERS * CS) as usize];
        let s = &mut bytes[..512];
        s[3..11].copy_from_slice(b"NTFS    ");
        s[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        s[0x0D] = 8;
        s[0x28..0x30].copy_from_slice(&(CLUSTERS * 8 - 1).to_le_bytes());
        s[0x30..0x38].copy_from_slice(&MFT_RUNS[0].0.to_le_bytes());
        s[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
        s[0x40] = 0xF6;
        s[0x44] = 1;
        s[510] = 0x55;
        s[511] = 0xAA;
        let mut img = Self { bytes, used: BTreeSet::new(), bitmap: true };
        img.mark(0, 4);
        for (lcn, len) in MFT_RUNS {
            img.mark(lcn, len);
        }
        let runs: Vec<(Option<i64>, u64)> = MFT_RUNS.iter().map(|(l, n)| (Some(*l as i64), *n)).collect();
        let size = MFT_RUNS.iter().map(|r| r.1).sum::<u64>() * CS;
        let mft = RecordBuilder::new(0, 1).std_info().file_name(fref(5, 5), "$MFT", 3).non_resident(0x80, "", 0, &runs, size);
        img.put(0, mft.build());
        let root = RecordBuilder::new(5, 5).dir().std_info().file_name(fref(5, 5), ".", 3);
        img.put(5, root.build());
        img
    }

    pub(super) fn mark(&mut self, lcn: u64, len: u64) {
        self.used.extend(lcn..lcn + len);
    }

    pub(super) fn without_bitmap(mut self) -> Self {
        self.bitmap = false;
        self
    }

    pub(super) fn record_offset(n: u64) -> usize {
        let per_cluster = CS / RS as u64;
        let mut first = 0;
        for (lcn, len) in MFT_RUNS {
            if n < first + len * per_cluster {
                return (lcn * CS) as usize + ((n - first) as usize) * RS;
            }
            first += len * per_cluster;
        }
        panic!("record {n} outside test MFT");
    }

    pub(super) fn put(&mut self, n: u64, record: Vec<u8>) {
        let off = Self::record_offset(n);
        self.bytes[off..off + RS].copy_from_slice(&record);
    }

    pub(super) fn write(&mut self, lcn: u64, data: &[u8]) {
        let off = (lcn * CS) as usize;
        self.bytes[off..off + data.len()].copy_from_slice(data);
        self.mark(lcn, (data.len() as u64).div_ceil(CS).max(1));
    }

    /// Raw write that leaves the clusters marked free (old data in free space).
    pub(super) fn write_free(&mut self, offset: usize, data: &[u8]) {
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }

    pub(super) fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub(super) fn finish(mut self) -> Vec<u8> {
        if self.bitmap {
            let mut bits = vec![0u8; (CLUSTERS / 8) as usize];
            for c in &self.used {
                bits[(c / 8) as usize] |= 1 << (c % 8);
            }
            let rec = RecordBuilder::new(6, 6).std_info().file_name(fref(5, 5), "$Bitmap", 3).resident(0x80, "", &bits);
            self.put(6, rec.build());
        }
        self.bytes
    }
}
