//! What the user asks for: a pattern, the encodings to look in, case handling and where on
//! the disk to look.

use crate::Encoding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Pattern {
    /// Text, encoded into each selected encoding.
    Text(String),
    /// Raw bytes.
    Hex(Vec<u8>),
    /// Regular expression over the byte view (ASCII/UTF-8) and, when a UTF-16 encoding is
    /// selected, over decoded UTF-16 text runs.
    Regex(String),
}

impl Pattern {
    /// Parse hex input: pairs of digits, spaces and `0x` prefixes ignored.
    pub fn hex(input: &str) -> Result<Self, String> {
        let digits: String = input.split_whitespace().map(|w| w.trim_start_matches("0x")).collect();
        if digits.is_empty() || !digits.len().is_multiple_of(2) || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Hex needs pairs of digits, like 4D 5A 90 00.".into());
        }
        let bytes = (0..digits.len()).step_by(2).filter_map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok()).collect();
        Ok(Self::Hex(bytes))
    }
}

/// Where on each disk to look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Scope {
    WholeDisk,
    /// Free clusters of every filesystem and disk space outside volumes.
    Unallocated,
    /// Content of deleted and orphaned files.
    DeletedFiles,
    /// One volume (by index).
    Volume(u32),
}

impl Scope {
    pub fn describe(self) -> String {
        match self {
            Self::WholeDisk => "whole disk".into(),
            Self::Unallocated => "free space".into(),
            Self::DeletedFiles => "deleted files".into(),
            Self::Volume(n) => format!("volume {n}"),
        }
    }

    /// `disk`, `unallocated`, `deleted`, `volume:N`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "disk" | "whole" | "all" => Some(Self::WholeDisk),
            "unallocated" | "free" => Some(Self::Unallocated),
            "deleted" => Some(Self::DeletedFiles),
            other => other.strip_prefix("volume:").and_then(|n| n.parse().ok()).map(Self::Volume),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub pattern: Pattern,
    pub encodings: Vec<Encoding>,
    pub case_insensitive: bool,
    pub scope: Scope,
}

impl SearchQuery {
    /// Text search in the usual encodings of Windows and Linux disks.
    pub fn text(text: &str) -> Self {
        Self {
            pattern: Pattern::Text(text.to_string()),
            encodings: vec![Encoding::Utf8, Encoding::Utf16Le, Encoding::Cp1251],
            case_insensitive: true,
            scope: Scope::WholeDisk,
        }
    }

    pub fn summary(&self) -> String {
        let what = match &self.pattern {
            Pattern::Text(t) => format!("\"{t}\""),
            Pattern::Hex(b) => b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "),
            Pattern::Regex(r) => format!("/{r}/"),
        };
        let encodings = match self.pattern {
            Pattern::Hex(_) => String::new(),
            _ => format!(" in {}", self.encodings.iter().map(|e| e.name()).collect::<Vec<_>>().join(", ")),
        };
        format!("{what}{encodings}, {}", self.scope.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_scope_parsing() {
        assert_eq!(Pattern::hex("4d 5A 0x90 00"), Ok(Pattern::Hex(vec![0x4D, 0x5A, 0x90, 0])));
        assert!(Pattern::hex("4d5").is_err());
        assert_eq!(Scope::parse("volume:2"), Some(Scope::Volume(2)));
        assert_eq!(Scope::parse("unallocated"), Some(Scope::Unallocated));
        let q = SearchQuery::text("seed");
        assert_eq!(q.summary(), "\"seed\" in UTF-8, UTF-16LE, CP1251, whole disk");
    }
}
