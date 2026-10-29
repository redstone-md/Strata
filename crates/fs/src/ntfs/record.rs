//! MFT `FILE` records: update-sequence fixups, header and attribute list.

use super::attr::Attribute;
use strata_kernel::bytes::{u16_le, u32_le, u64_le};
use strata_kernel::{ByteRange, Damage};

/// NTFS protects every 512-byte stride of a record with the update sequence number.
const FIXUP_STRIDE: usize = 512;
const MAX_ATTRIBUTES: usize = 512;
const FLAG_IN_USE: u16 = 0x0001;
const FLAG_DIRECTORY: u16 = 0x0002;

/// File reference: 48-bit record number + 16-bit sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct FileRef(u64);

impl FileRef {
    pub(super) fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub(super) fn record(self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_FFFF
    }

    pub(super) fn seq(self) -> u16 {
        (self.0 >> 48) as u16
    }

    /// Does this reference still name a record with sequence `seq`? NTFS bumps the sequence
    /// when it frees a record, so a free record one step ahead is the same (deleted) file.
    /// Sequence 0 means "unchecked".
    pub(super) fn points_to(self, seq: u16, in_use: bool) -> bool {
        self.seq() == 0 || self.seq() == seq || (!in_use && self.seq().wrapping_add(1) == seq)
    }
}

pub(super) struct MftRecord {
    number: u64,
    seq: u16,
    flags: u16,
    base: FileRef,
    attrs: Vec<Attribute>,
    damage: Vec<Damage>,
}

impl MftRecord {
    /// Parse one record in place (fixups are applied to `raw`). `None` when the bytes are not a
    /// record at all (unused slot, garbage). `stored_number` uses the number written in the
    /// header (XP and later) instead of `number`, for carved records.
    pub(super) fn parse(raw: &mut [u8], number: u64, volume_offset: u64, stored_number: bool) -> Option<Self> {
        let sig = raw.get(..4)?;
        let mut damage = Vec::new();
        let at = ByteRange::new(volume_offset, raw.len() as u64);
        match sig {
            b"FILE" => {}
            b"BAAD" => damage.push(Damage::corrupt(at, "MFT record marked BAAD")),
            _ => return None,
        }
        Self::apply_fixups(raw, at, &mut damage);
        let usa_offset = u16_le(raw, 4)?;
        let header_number = (usa_offset >= 0x30).then(|| u32_le(raw, 0x2C)).flatten().map(u64::from);
        let number = match (stored_number, header_number) {
            (true, Some(n)) => n,
            _ => number,
        };
        let mut record = Self {
            number,
            seq: u16_le(raw, 0x10)?,
            flags: u16_le(raw, 0x16)?,
            base: FileRef::from_raw(u64_le(raw, 0x20)?),
            attrs: Vec::new(),
            damage,
        };
        record.parse_attributes(raw, at);
        Some(record)
    }

    fn apply_fixups(raw: &mut [u8], at: ByteRange, damage: &mut Vec<Damage>) {
        let (Some(off), Some(count)) = (u16_le(raw, 4), u16_le(raw, 6)) else { return };
        let (off, count) = (usize::from(off), usize::from(count));
        let strides = raw.len() / FIXUP_STRIDE;
        if count == 0 || count - 1 > strides || off + 2 * count > raw.len() || off < 0x28 {
            damage.push(Damage::corrupt(at, "MFT record update sequence array invalid"));
            return;
        }
        let usn = [raw[off], raw[off + 1]];
        let mut bad = Vec::new();
        for i in 1..count {
            let pos = i * FIXUP_STRIDE - 2;
            if raw[pos..pos + 2] == usn {
                raw[pos] = raw[off + 2 * i];
                raw[pos + 1] = raw[off + 2 * i + 1];
            } else {
                bad.push(i - 1);
            }
        }
        if !bad.is_empty() {
            damage.push(Damage::corrupt(at, format!("MFT record fixup mismatch in sector(s) {bad:?}; torn write, kept as is")));
        }
    }

    fn parse_attributes(&mut self, raw: &[u8], at: ByteRange) {
        let Some(first) = u16_le(raw, 0x14) else { return };
        let used = u32_le(raw, 0x18).map_or(raw.len(), |u| (u as usize).min(raw.len()));
        let mut off = usize::from(first);
        for _ in 0..MAX_ATTRIBUTES {
            if off >= used {
                return;
            }
            let Some(type_code) = u32_le(raw, off) else { break };
            if type_code == 0xFFFF_FFFF {
                return;
            }
            let len = u32_le(raw, off + 4).map_or(0, |l| l as usize);
            let end = off.checked_add(len).filter(|e| len >= 16 && *e <= raw.len());
            let Some(end) = end else {
                self.damage.push(Damage::corrupt(at, format!("attribute at +{off:#x} has bad length {len}")));
                return;
            };
            if let Some(attr) = Attribute::parse(&raw[off..end]).filter(Attribute::is_interesting) {
                self.attrs.push(attr);
            }
            off = end;
        }
        self.damage.push(Damage::corrupt(at, "attribute chain not terminated"));
    }

    pub(super) fn number(&self) -> u64 {
        self.number
    }

    pub(super) fn seq(&self) -> u16 {
        self.seq
    }

    pub(super) fn in_use(&self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    pub(super) fn is_dir(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    /// Base record this extension record belongs to, `None` for base records.
    pub(super) fn base(&self) -> Option<FileRef> {
        (self.base.record() != 0 || self.base.seq() != 0).then_some(self.base).filter(|b| b.record() != self.number)
    }

    pub(super) fn attrs(&self) -> &[Attribute] {
        &self.attrs
    }

    pub(super) fn damage(&self) -> &[Damage] {
        &self.damage
    }
}
