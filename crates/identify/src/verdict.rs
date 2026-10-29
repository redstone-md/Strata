//! The answer to "what is this file, how intact is it, and was it renamed?".

use crate::profile::BlockProfile;
use crate::registry::{Category, TypeId};
use serde::{Deserialize, Serialize};
use strata_kernel::{Confidence, Damage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InnerKind {
    /// Archive member (ZIP/TAR entry).
    Member,
    /// OLE2 stream or storage.
    Stream,
    /// Database table.
    Table,
    /// Countable structural object (PDF objects, pages, records).
    Object,
    /// Executable section.
    Section,
    /// `key=value` fact (dimensions, encoding, brand, machine...).
    Property,
}

/// Something found inside the identified file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerItem {
    pub kind: InnerKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

impl InnerItem {
    pub fn new(kind: InnerKind, name: impl Into<String>, size: Option<u64>) -> Self {
        Self { kind, name: name.into(), size }
    }
}

/// The declared extension does not belong to the detected type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionMismatch {
    pub declared: String,
    pub actual: TypeId,
    /// Extensions the detected type normally uses.
    pub expected: Vec<String>,
    /// Valuable content (archive, wallet, database...) disguised as something mundane.
    pub suspicious: bool,
    pub reason: String,
}

/// How the type was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Header magic matched and the structural validator agreed.
    Header,
    /// Header missing or corrupt; type inferred from internal structures.
    Structure,
    /// Inferred from text statistics.
    Text,
    /// Inferred from the entropy profile only.
    Entropy,
    /// Nothing recognisable.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeVerdict {
    pub file_type: TypeId,
    pub type_name: String,
    pub category: Category,
    pub confidence: Confidence,
    pub method: Method,
    /// 0..=1: how much of the structure validated (and is not zero-filled).
    pub valid_fraction: f32,
    pub damage: Vec<Damage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_mismatch: Option<ExtensionMismatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_len: Option<u64>,
    pub notes: Vec<String>,
    pub inner: Vec<InnerItem>,
    pub profile: BlockProfile,
}

impl TypeVerdict {
    pub fn is_known(&self) -> bool {
        !matches!(self.file_type, TypeId::Unknown)
    }

    pub fn is_damaged(&self) -> bool {
        !self.damage.is_empty() || self.valid_fraction < 0.999
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}
