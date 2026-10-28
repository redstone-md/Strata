use crate::ByteRange;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DamageKind {
    /// Medium could not be read (bad sector, block missing from image).
    Unreadable,
    /// Bytes were read but fail structural validation.
    Corrupt,
    /// Structure ends before its declared size.
    Truncated,
    /// Referenced data is absent (overwritten cluster, missing archive part).
    Missing,
}

/// A defect found while reading or parsing. Parsers collect these instead of failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Damage {
    kind: DamageKind,
    range: Option<ByteRange>,
    note: String,
}

impl Damage {
    pub fn new(kind: DamageKind, range: Option<ByteRange>, note: impl Into<String>) -> Self {
        Self { kind, range, note: note.into() }
    }

    pub fn corrupt(range: ByteRange, note: impl Into<String>) -> Self {
        Self::new(DamageKind::Corrupt, Some(range), note)
    }

    pub fn truncated(note: impl Into<String>) -> Self {
        Self::new(DamageKind::Truncated, None, note)
    }

    pub fn missing(range: Option<ByteRange>, note: impl Into<String>) -> Self {
        Self::new(DamageKind::Missing, range, note)
    }

    pub fn kind(&self) -> DamageKind {
        self.kind
    }

    pub fn range(&self) -> Option<ByteRange> {
        self.range
    }

    pub fn note(&self) -> &str {
        &self.note
    }
}
