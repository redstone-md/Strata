//! Result of one structural check (header validator or headerless evidence scanner).

use crate::registry::TypeId;
use crate::verdict::{InnerItem, InnerKind};
use strata_kernel::{Confidence, Damage};

/// What a single format check found. Builders keep validators short.
#[derive(Debug, Clone)]
pub struct Probe {
    pub(crate) id: TypeId,
    pub(crate) confidence: Confidence,
    /// Fraction (0..=1) of the structure that validated.
    pub(crate) structure: f32,
    /// Total file length announced by the format's own headers.
    pub(crate) declared_len: Option<u64>,
    pub(crate) damage: Vec<Damage>,
    pub(crate) notes: Vec<String>,
    pub(crate) inner: Vec<InnerItem>,
}

impl Probe {
    pub fn new(id: TypeId, confidence: Confidence) -> Self {
        Self {
            id,
            confidence,
            structure: 1.0,
            declared_len: None,
            damage: Vec::new(),
            notes: Vec::new(),
            inner: Vec::new(),
        }
    }

    /// Strong header magic plus a passing validator.
    pub fn certain(id: TypeId) -> Self {
        Self::new(id, Confidence::new(0.95))
    }

    pub fn id(&self) -> TypeId {
        self.id
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn structure(&self) -> f32 {
        self.structure
    }

    pub fn declared_len(&self) -> Option<u64> {
        self.declared_len
    }

    pub fn damage(&self) -> &[Damage] {
        &self.damage
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn inner(&self) -> &[InnerItem] {
        &self.inner
    }

    pub(crate) fn with_structure(mut self, fraction: f32) -> Self {
        self.structure = if fraction.is_nan() { 0.0 } else { fraction.clamp(0.0, 1.0) };
        self
    }

    pub(crate) fn with_len(mut self, len: Option<u64>) -> Self {
        self.declared_len = len.filter(|l| *l > 0);
        self
    }

    pub(crate) fn with_confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    pub(crate) fn refine(mut self, id: TypeId) -> Self {
        self.id = id;
        self
    }

    pub(crate) fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub(crate) fn damaged(&mut self, damage: Damage) {
        self.damage.push(damage);
    }

    pub(crate) fn item(&mut self, kind: InnerKind, name: impl Into<String>, size: Option<u64>) {
        self.inner.push(InnerItem::new(kind, name, size));
    }

    pub(crate) fn property(&mut self, name: &str, value: impl std::fmt::Display) {
        self.inner.push(InnerItem::new(InnerKind::Property, format!("{name}={value}"), None));
    }

    /// Ranking used to pick between competing probes.
    pub(crate) fn score(&self) -> f32 {
        self.confidence.get() * (0.5 + 0.5 * self.structure)
    }
}

/// Validated ratio helper: `ok / total`, 0 when nothing was examined.
pub(crate) fn ratio(ok: usize, total: usize) -> f32 {
    if total == 0 { 0.0 } else { ok as f32 / total as f32 }
}
