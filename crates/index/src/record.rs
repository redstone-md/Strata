//! One block's entry in the index, bit-packed into a `u16`.
//!
//! ```text
//! bits 0-2   content class      (Unscanned, Zero, Fill, Text, Random, Binary, Unreadable)
//! bits 3-4   text encoding      (Ascii, Utf8, Utf16, SingleByte8) when the class is Text
//! bits 5-8   entropy bucket     (0..=15, half-bit steps of bits/byte)
//! bit  9     has a file signature starting in the block
//! bit  10    has a finding (key, wallet, seed, address, identity)
//! bits 11-13 ownership          (Unknown, LiveFile, Unallocated, DeletedFile, OutsideVolumes)
//! bit  14    has a recognised boot sector / superblock
//! bit  15    seeded             (content class came from an imported scan, not our own pass)
//! ```

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockClass {
    /// Not looked at yet.
    Unscanned = 0,
    Zero = 1,
    /// One byte value repeated (0xFF erase pattern, padding).
    Fill = 2,
    Text = 3,
    /// Close to 8 bits/byte: compressed or encrypted.
    Random = 4,
    /// Everything else: tables, code, headers, mixed content.
    Binary = 5,
    /// The medium could not be read.
    Unreadable = 6,
}

impl BlockClass {
    pub const ALL: [BlockClass; 7] = [
        BlockClass::Unscanned,
        BlockClass::Zero,
        BlockClass::Fill,
        BlockClass::Text,
        BlockClass::Random,
        BlockClass::Binary,
        BlockClass::Unreadable,
    ];

    fn from_bits(v: u16) -> Self {
        Self::ALL.get(usize::from(v)).copied().unwrap_or(BlockClass::Unscanned)
    }

    /// Blocks that can hold something worth reading (not empty, not unreadable).
    pub fn has_content(self) -> bool {
        matches!(self, BlockClass::Text | BlockClass::Random | BlockClass::Binary | BlockClass::Unscanned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextKind {
    Ascii = 0,
    Utf8 = 1,
    Utf16 = 2,
    /// 8-bit code page text (CP1251, CP1252, KOI8...).
    SingleByte8 = 3,
}

impl TextKind {
    const ALL: [TextKind; 4] = [TextKind::Ascii, TextKind::Utf8, TextKind::Utf16, TextKind::SingleByte8];
}

/// Who the block belongs to according to the parsed filesystems. When a block is shared, the
/// most interesting owner wins (outside volumes > deleted file > unallocated > live file), so
/// "live file" always means the whole block is allocated. A deleted file's block is
/// unallocated space a deleted entry still points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Unknown = 0,
    LiveFile = 1,
    Unallocated = 2,
    DeletedFile = 3,
    OutsideVolumes = 4,
}

impl Ownership {
    pub const ALL: [Ownership; 5] =
        [Ownership::Unknown, Ownership::LiveFile, Ownership::Unallocated, Ownership::DeletedFile, Ownership::OutsideVolumes];

    fn from_bits(v: u16) -> Self {
        Self::ALL.get(usize::from(v)).copied().unwrap_or(Ownership::Unknown)
    }

    /// Space no live file claims: where carving and deleted-data search look.
    pub fn is_free(self) -> bool {
        matches!(self, Ownership::DeletedFile | Ownership::Unallocated | Ownership::OutsideVolumes)
    }
}

const CLASS_MASK: u16 = 0b111;
const TEXT_SHIFT: u16 = 3;
const TEXT_MASK: u16 = 0b11 << TEXT_SHIFT;
const ENTROPY_SHIFT: u16 = 5;
const ENTROPY_MASK: u16 = 0b1111 << ENTROPY_SHIFT;
pub(crate) const SIGNATURE: u16 = 1 << 9;
pub(crate) const FINDING: u16 = 1 << 10;
const OWNER_SHIFT: u16 = 11;
pub(crate) const OWNER_MASK: u16 = 0b111 << OWNER_SHIFT;
pub(crate) const BOOT: u16 = 1 << 14;
pub(crate) const SEEDED: u16 = 1 << 15;
/// Bits describing content (written by a profiler); the rest are annotations.
pub(crate) const CONTENT_MASK: u16 = CLASS_MASK | TEXT_MASK | ENTROPY_MASK | SEEDED;

/// Packed per-block record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct BlockRecord(u16);

impl BlockRecord {
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    /// A content record: class, text encoding (ignored unless Text) and entropy in bits/byte.
    pub fn content(class: BlockClass, text: TextKind, entropy: f32) -> Self {
        let bucket = (entropy.clamp(0.0, 8.0) * 2.0).round().min(15.0) as u16;
        let text = if class == BlockClass::Text { text as u16 } else { 0 };
        Self(class as u16 | text << TEXT_SHIFT | bucket << ENTROPY_SHIFT)
    }

    pub fn class(self) -> BlockClass {
        BlockClass::from_bits(self.0 & CLASS_MASK)
    }

    pub fn text_kind(self) -> Option<TextKind> {
        (self.class() == BlockClass::Text).then(|| TextKind::ALL[usize::from((self.0 & TEXT_MASK) >> TEXT_SHIFT)])
    }

    /// Entropy bucket 0..=15 (bucket / 2 ≈ bits per byte).
    pub fn entropy_bucket(self) -> u8 {
        ((self.0 & ENTROPY_MASK) >> ENTROPY_SHIFT) as u8
    }

    pub fn has_signature(self) -> bool {
        self.0 & SIGNATURE != 0
    }

    pub fn has_finding(self) -> bool {
        self.0 & FINDING != 0
    }

    pub fn has_boot_record(self) -> bool {
        self.0 & BOOT != 0
    }

    pub fn is_seeded(self) -> bool {
        self.0 & SEEDED != 0
    }

    pub fn ownership(self) -> Ownership {
        Ownership::from_bits((self.0 & OWNER_MASK) >> OWNER_SHIFT)
    }

    pub fn with_flags(self, flags: u16) -> Self {
        Self(self.0 | flags)
    }

    pub fn with_ownership(self, owner: Ownership) -> Self {
        Self(self.0 & !OWNER_MASK | (owner as u16) << OWNER_SHIFT)
    }

    /// Replace the content bits, keep the annotations.
    pub fn with_content_of(self, content: BlockRecord) -> Self {
        Self(self.0 & !CONTENT_MASK | content.0 & CONTENT_MASK)
    }

    pub fn seeded(self) -> Self {
        Self(self.0 | SEEDED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_every_field_independently() {
        let r = BlockRecord::content(BlockClass::Text, TextKind::Utf16, 4.3)
            .with_flags(SIGNATURE | BOOT)
            .with_ownership(Ownership::DeletedFile);
        assert_eq!(r.class(), BlockClass::Text);
        assert_eq!(r.text_kind(), Some(TextKind::Utf16));
        assert_eq!(r.entropy_bucket(), 9);
        assert!(r.has_signature() && r.has_boot_record() && !r.has_finding() && !r.is_seeded());
        assert_eq!(r.ownership(), Ownership::DeletedFile);
        let replaced = r.with_content_of(BlockRecord::content(BlockClass::Random, TextKind::Ascii, 8.0));
        assert_eq!((replaced.class(), replaced.text_kind(), replaced.entropy_bucket()), (BlockClass::Random, None, 15));
        assert_eq!(replaced.ownership(), Ownership::DeletedFile);
        assert!(replaced.has_signature());
    }

    #[test]
    fn unknown_bit_patterns_decode_safely() {
        let r = BlockRecord::from_bits(0b111 | 0b111 << 11);
        assert_eq!(r.class(), BlockClass::Unscanned);
        assert_eq!(r.ownership(), Ownership::Unknown);
    }
}
