//! Attribute headers: resident values and non-resident run lists.

use super::runs::Run;
use strata_kernel::bytes::{u16_le, u32_le, u64_le, u8_at, utf16le};

pub(super) const STANDARD_INFORMATION: u32 = 0x10;
pub(super) const ATTRIBUTE_LIST: u32 = 0x20;
pub(super) const FILE_NAME: u32 = 0x30;
pub(super) const DATA: u32 = 0x80;

const FLAG_COMPRESSED: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 0x4000;

pub(super) struct NonResident {
    start_vcn: u64,
    runs: Vec<Run>,
    runs_clean: bool,
    size: u64,
    initialized: u64,
    compression_unit: u8,
}

impl NonResident {
    pub(super) fn start_vcn(&self) -> u64 {
        self.start_vcn
    }

    pub(super) fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// The run list decoded without hitting garbage.
    pub(super) fn runs_clean(&self) -> bool {
        self.runs_clean
    }

    /// Logical size; meaningful on the instance with `start_vcn == 0`.
    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn initialized(&self) -> u64 {
        self.initialized
    }

    /// Compression unit as log2(clusters); 0 = not compressed.
    pub(super) fn compression_unit(&self) -> u8 {
        self.compression_unit
    }
}

enum AttrBody {
    Resident(Vec<u8>),
    NonResident(NonResident),
}

pub(super) struct Attribute {
    type_code: u32,
    name: String,
    flags: u16,
    body: AttrBody,
}

impl Attribute {
    /// Parse one attribute from exactly its `length` bytes.
    pub(super) fn parse(a: &[u8]) -> Option<Self> {
        let type_code = u32_le(a, 0)?;
        let non_resident = u8_at(a, 8)? != 0;
        let name_len = usize::from(u8_at(a, 9)?);
        let name_off = usize::from(u16_le(a, 0x0A)?);
        let name = if name_len == 0 { String::new() } else { utf16le(a.get(name_off..name_off + 2 * name_len)?) };
        let flags = u16_le(a, 0x0C)?;
        let body = if non_resident { AttrBody::NonResident(Self::parse_non_resident(a)?) } else { Self::resident(a)? };
        Some(Self { type_code, name, flags, body })
    }

    fn resident(a: &[u8]) -> Option<AttrBody> {
        let len = u32_le(a, 0x10)? as usize;
        let off = usize::from(u16_le(a, 0x14)?);
        // A value running past the attribute is truncated, not dropped.
        let end = off.saturating_add(len).min(a.len());
        Some(AttrBody::Resident(a.get(off..end)?.to_vec()))
    }

    fn parse_non_resident(a: &[u8]) -> Option<NonResident> {
        let start_vcn = u64_le(a, 0x10)?;
        let runs_off = usize::from(u16_le(a, 0x20)?);
        let (runs, runs_clean) = super::runs::decode(a.get(runs_off..).unwrap_or_default(), start_vcn);
        Some(NonResident {
            start_vcn,
            runs,
            runs_clean,
            size: u64_le(a, 0x30)?,
            initialized: u64_le(a, 0x38)?,
            compression_unit: u8_at(a, 0x22)?,
        })
    }

    /// Only the attributes the file model needs are kept in memory.
    pub(super) fn is_interesting(&self) -> bool {
        matches!(self.type_code, STANDARD_INFORMATION | ATTRIBUTE_LIST | FILE_NAME | DATA)
    }

    pub(super) fn type_code(&self) -> u32 {
        self.type_code
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    pub(super) fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub(super) fn resident_value(&self) -> Option<&[u8]> {
        match &self.body {
            AttrBody::Resident(v) => Some(v),
            AttrBody::NonResident(_) => None,
        }
    }

    pub(super) fn non_resident(&self) -> Option<&NonResident> {
        match &self.body {
            AttrBody::NonResident(n) => Some(n),
            AttrBody::Resident(_) => None,
        }
    }
}
