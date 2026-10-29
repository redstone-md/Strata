//! Sightings of wallet files, and which of them are the same file. Two sightings are one file
//! when they name the same path (on any disk), carry the same hash, the same name and size,
//! or the same wallet content (shared addresses or crack hash). A bare name (`wallet.dat` in
//! RecentDocs) joins the one full path with that name, if there is exactly one.

use crate::inputs::{ArchiveMember, FileRecord, MailAttachment, WalletHit};
use crate::path_key::PathKey;
use crate::traces::Reference;
use std::collections::HashMap;
use strata_kernel::{EvidenceId, Timestamp};

/// One place or trace of a wallet-relevant file.
#[derive(Debug, Clone)]
pub(crate) enum Seen<'a> {
    Reference(Reference<'a>),
    File(&'a FileRecord),
    Hit(&'a WalletHit),
    Member(&'a ArchiveMember),
    Attachment(&'a MailAttachment),
}

#[derive(Debug, Clone)]
pub(crate) struct Sighting<'a> {
    pub key: PathKey,
    pub seen: Seen<'a>,
}

impl<'a> Sighting<'a> {
    pub fn reference(r: Reference<'a>) -> Self {
        Self { key: r.key.clone(), seen: Seen::Reference(r) }
    }

    pub fn file(f: &'a FileRecord) -> Self {
        Self { key: PathKey::of(&f.path), seen: Seen::File(f) }
    }

    /// Findings in a file share its key; free-space findings get one of their own.
    pub fn hit(h: &'a WalletHit) -> Self {
        let key = h.file_path.as_deref().map_or_else(|| PathKey::of(&format!("@{}/{:x}", h.evidence.get(), h.offset)), PathKey::of);
        Self { key, seen: Seen::Hit(h) }
    }

    pub fn member(m: &'a ArchiveMember) -> Self {
        Self { key: PathKey::of(&m.member_path), seen: Seen::Member(m) }
    }

    pub fn attachment(a: &'a MailAttachment) -> Self {
        Self { key: PathKey::of(&format!("mail:{}/{}", a.message, a.name)), seen: Seen::Attachment(a) }
    }

    pub fn evidence(&self) -> EvidenceId {
        match &self.seen {
            Seen::Reference(r) => r.record.evidence,
            Seen::File(f) => f.evidence,
            Seen::Hit(h) => h.evidence,
            Seen::Member(m) => m.evidence,
            Seen::Attachment(a) => a.evidence,
        }
    }

    /// The file's own name (`wallet.dat`), whatever the key.
    pub fn name(&self) -> String {
        match &self.seen {
            Seen::Attachment(a) => a.name.to_lowercase(),
            _ => self.key.name().to_string(),
        }
    }

    /// File size, where the sighting knows it.
    pub fn size(&self) -> Option<u64> {
        match &self.seen {
            Seen::Reference(r) => r.size,
            Seen::File(f) => Some(f.size),
            Seen::Member(m) => m.size,
            Seen::Attachment(a) => Some(a.size),
            Seen::Hit(_) => None,
        }
        .filter(|s| *s > 0)
    }

    /// Dates the sighting itself carries.
    pub fn times(&self) -> Vec<Timestamp> {
        match &self.seen {
            Seen::Reference(r) => vec![r.record.event.at()],
            Seen::File(f) => [f.created, f.modified, f.changed].into_iter().flatten().collect(),
            Seen::Member(m) => m.modified.into_iter().collect(),
            Seen::Attachment(a) => a.at.into_iter().collect(),
            Seen::Hit(_) => Vec::new(),
        }
    }
}

/// Disjoint sets over sighting indexes.
struct Union {
    parent: Vec<usize>,
}

impl Union {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect() }
    }

    fn find(&mut self, mut i: usize) -> usize {
        while self.parent[i] != i {
            self.parent[i] = self.parent[self.parent[i]];
            i = self.parent[i];
        }
        i
    }

    fn join(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra.max(rb)] = ra.min(rb);
        }
    }

    /// Join every index that shares a value of `key` with the first one seen.
    fn join_by<K: std::hash::Hash + Eq>(&mut self, keys: impl Iterator<Item = (usize, K)>) {
        let mut first: HashMap<K, usize> = HashMap::new();
        for (i, k) in keys {
            match first.get(&k) {
                Some(&j) => self.join(i, j),
                None => {
                    first.insert(k, i);
                }
            }
        }
    }
}

/// Group sightings into files: each group lists sighting indexes in input order.
pub(crate) fn clusters(sightings: &[Sighting<'_>]) -> Vec<Vec<usize>> {
    let mut u = Union::new(sightings.len());
    let full = |s: &Sighting<'_>| !s.key.is_bare();
    u.join_by(sightings.iter().enumerate().filter(|(_, s)| full(s)).map(|(i, s)| (i, s.key.as_str().to_string())));
    // A bare name joins the only full path with that name; bare names with several candidates
    // stay together on their own.
    let mut full_by_name: HashMap<String, Vec<&str>> = HashMap::new();
    for s in sightings.iter().filter(|s| full(s) && !matches!(s.seen, Seen::Hit(h) if h.is_free())) {
        let paths = full_by_name.entry(s.name()).or_default();
        if !paths.contains(&s.key.as_str()) {
            paths.push(s.key.as_str());
        }
    }
    let mut bare_targets: Vec<(usize, String)> = Vec::new();
    for (i, s) in sightings.iter().enumerate().filter(|(_, s)| !full(s)) {
        match full_by_name.get(&s.name()).map(Vec::as_slice) {
            Some([only]) => bare_targets.push((i, format!("path:{only}"))),
            _ => bare_targets.push((i, format!("name:{}", s.name()))),
        }
    }
    let path_index: HashMap<&str, usize> = sightings.iter().enumerate().filter(|(_, s)| full(s)).map(|(i, s)| (s.key.as_str(), i)).collect();
    for (i, target) in &bare_targets {
        if let Some(j) = target.strip_prefix("path:").and_then(|p| path_index.get(p)) {
            u.join(*i, *j);
        }
    }
    u.join_by(bare_targets.iter().filter(|(_, t)| t.starts_with("name:")).map(|(i, t)| (*i, t.clone())));
    // Same content: hash, wallet addresses, crack hash.
    u.join_by(sightings.iter().enumerate().filter_map(|(i, s)| match s.seen {
        Seen::File(f) => f.sha256.clone().filter(|h| !h.is_empty() && f.size > 0).map(|h| (i, h)),
        _ => None,
    }));
    u.join_by(sightings.iter().enumerate().flat_map(|(i, s)| match s.seen {
        Seen::Hit(h) => h.addresses.iter().map(|a| (i, format!("addr:{a}"))).chain(h.fingerprint.iter().map(|f| (i, format!("fp:{f}")))).collect::<Vec<_>>(),
        _ => Vec::new(),
    }));
    // Same name and size: a copy, a move, an archived or mailed copy.
    u.join_by(sightings.iter().enumerate().filter_map(|(i, s)| s.size().map(|size| (i, (s.name(), size)))));
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..sightings.len() {
        groups.entry(u.find(i)).or_default().push(i);
    }
    let mut out: Vec<Vec<usize>> = groups.into_values().collect();
    out.sort_by_key(|g| g[0]);
    out
}
