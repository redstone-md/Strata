//! Deduplicated values with provenance: the same computer name read from SYSTEM, its
//! `RegBack` copy and a restore point is one value with three sources.

use serde::Serialize;
use strata_kernel::Timestamp;

/// Where a value was read: parser id and evidence file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct SourceRef {
    pub artifact: String,
    pub path: String,
}

impl SourceRef {
    pub fn new(artifact: impl Into<String>, path: impl Into<String>) -> Self {
        Self { artifact: artifact.into(), path: path.into() }
    }

    /// Short hint for a UI: the file name (`SYSTEM`, `NTUSER.DAT`, `os-release`).
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['/', '\\']).find(|p| !p.is_empty()).unwrap_or(&self.artifact)
    }

    /// Live system files beat setup copies (`repair`), registry backups (`RegBack`) and restore
    /// points: a lower rank is more authoritative.
    fn rank(&self) -> u8 {
        let p = self.path.to_lowercase();
        const COPIES: &[&str] = &["repair", "regback", "_restore", "snapshot", "windows.old", ".bak", "backup"];
        u8::from(COPIES.iter().any(|c| p.contains(c)))
    }
}

/// Sources kept per value; the rest are only counted.
const MAX_SOURCES: usize = 4;

/// One distinct value and where it was seen.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sourced<T> {
    pub value: T,
    pub sources: Vec<SourceRef>,
    /// Times it was read (more than `sources` holds when many files agree).
    pub seen: usize,
}

impl<T> Sourced<T> {
    pub fn source(&self) -> Option<&SourceRef> {
        self.sources.first()
    }

    fn add_source(&mut self, source: SourceRef) {
        self.seen += 1;
        if self.sources.len() < MAX_SOURCES && !self.sources.contains(&source) {
            self.sources.push(source);
        }
        self.sources.sort_by_key(SourceRef::rank);
    }

    fn rank(&self) -> u8 {
        self.sources.iter().map(SourceRef::rank).min().unwrap_or(u8::MAX)
    }
}

/// Distinct values of one field in first-seen order; [`Values::primary`] picks the one to show.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Values<T> {
    items: Vec<Sourced<T>>,
}

impl<T> Default for Values<T> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

/// Equality used for deduplication (case-insensitive for text).
pub trait SameValue {
    fn same(&self, other: &Self) -> bool;
}

impl SameValue for String {
    fn same(&self, other: &Self) -> bool {
        self.trim().eq_ignore_ascii_case(other.trim())
    }
}

impl SameValue for i32 {
    fn same(&self, other: &Self) -> bool {
        self == other
    }
}

/// A timestamp field value, written as `YYYY-MM-DD HH:MM:SS` in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct When(pub Timestamp);

impl Serialize for When {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl SameValue for When {
    fn same(&self, other: &Self) -> bool {
        self == other
    }
}

impl<T: SameValue> Values<T> {
    pub fn add(&mut self, value: T, source: SourceRef) {
        match self.items.iter_mut().find(|i| i.value.same(&value)) {
            Some(item) => item.add_source(source),
            None => {
                let mut item = Sourced { value, sources: Vec::new(), seen: 0 };
                item.add_source(source);
                self.items.push(item);
            }
        }
    }

    /// Fold in another field's values (merging two installations into one).
    pub fn merge(&mut self, other: Values<T>) {
        for item in other.items {
            match self.items.iter_mut().find(|i| i.value.same(&item.value)) {
                Some(mine) => {
                    // `add_source` counts one sighting per source; the rest are carried over.
                    let extra = item.seen.saturating_sub(item.sources.len());
                    for source in item.sources {
                        mine.add_source(source);
                    }
                    mine.seen += extra;
                }
                None => self.items.push(item),
            }
        }
    }
}

impl<T> Values<T> {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Sourced<T>> {
        self.items.iter()
    }

    /// The value to show: read from the most authoritative file, then the most often seen.
    pub fn primary(&self) -> Option<&Sourced<T>> {
        self.primary_index().and_then(|i| self.items.get(i))
    }

    fn primary_index(&self) -> Option<usize> {
        self.items.iter().enumerate().min_by_key(|(i, s)| (s.rank(), std::cmp::Reverse(s.seen), *i)).map(|(i, _)| i)
    }

    pub fn value(&self) -> Option<&T> {
        self.primary().map(|s| &s.value)
    }

    /// Values other than the primary one.
    pub fn others(&self) -> impl Iterator<Item = &Sourced<T>> {
        let primary = self.primary_index();
        self.items.iter().enumerate().filter(move |(i, _)| Some(*i) != primary).map(|(_, s)| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_and_prefers_live_files() {
        let mut v = Values::default();
        v.add("OLD-NAME".to_string(), SourceRef::new("registry.system", "WINDOWS/repair/system"));
        v.add("HOME-PC".to_string(), SourceRef::new("registry.system", "WINDOWS/system32/config/SYSTEM"));
        v.add("home-pc".to_string(), SourceRef::new("registry.system", "System Volume Information/_restore{1}/RP2/snapshot/_REGISTRY_MACHINE_SYSTEM"));
        assert_eq!(v.len(), 2);
        assert_eq!(v.value().map(String::as_str), Some("HOME-PC"));
        let p = v.primary().unwrap();
        assert_eq!((p.seen, p.sources.len(), p.source().unwrap().file_name()), (2, 2, "SYSTEM"));
        assert_eq!(v.others().map(|s| s.value.as_str()).collect::<Vec<_>>(), ["OLD-NAME"]);
    }
}
