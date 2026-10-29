//! Application service of the context: walk a filesystem (live, deleted and orphan entries),
//! pick artefact files by path, parse them and merge everything into one result.

mod fs_events;
mod kind;

pub use fs_events::{FsEvents, fs_events};
pub use kind::ArtifactKind;

use crate::mail::ImPaths;
use crate::results::{ArtifactResults, Recorder};
use serde::{Deserialize, Serialize};
use strata_fs::{FileEntry, FileId, FileSystem};
use strata_kernel::{Damage, DamageKind};
use strata_timeline::EventKind;

/// Profile folders that are not a person.
const NON_USERS: &[&str] = &["all users", "default user", "default", "public", "localservice", "networkservice"];

/// What to extract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileHints {
    /// Only these user profiles (case-insensitive); empty = every profile and system files.
    pub users: Vec<String>,
    /// Parse deleted and orphan entries too (default: yes — deleted browser databases are gold).
    pub include_deleted: bool,
    /// Global per-file size cap in bytes (each artefact kind also has its own cap).
    pub max_file_size: u64,
}

impl Default for ProfileHints {
    fn default() -> Self {
        Self { users: Vec::new(), include_deleted: true, max_file_size: 512 << 20 }
    }
}

/// User profile name from a path (`Documents and Settings/<user>/…`, `Users/<user>/…`).
pub fn profile_of(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let i = parts.iter().position(|p| p.eq_ignore_ascii_case("documents and settings") || p.eq_ignore_ascii_case("users"))?;
    let user = parts.get(i + 1)?;
    (!NON_USERS.iter().any(|n| user.eq_ignore_ascii_case(n)) && i + 2 < parts.len()).then(|| user.to_string())
}

/// Parse carved or exported bytes. `None` when the bytes are not a known artefact.
pub fn parse_bytes(name_hint: &str, bytes: &[u8]) -> Option<ArtifactResults> {
    let kind = ArtifactKind::sniff(name_hint, bytes)?;
    let mut out = kind.parse(name_hint, bytes);
    out.attach(name_hint, false, profile_of(name_hint).as_deref());
    out.tag();
    Some(out)
}

pub struct ArtifactExtractor {
    hints: ProfileHints,
}

impl Default for ArtifactExtractor {
    fn default() -> Self {
        Self::new(ProfileHints::default())
    }
}

impl ArtifactExtractor {
    pub fn new(hints: ProfileHints) -> Self {
        Self { hints }
    }

    pub fn hints(&self) -> &ProfileHints {
        &self.hints
    }

    fn wanted(&self, entry: &FileEntry) -> bool {
        if entry.is_dir || (entry.is_deleted() && !self.hints.include_deleted) {
            return false;
        }
        if self.hints.users.is_empty() {
            return true;
        }
        profile_of(&entry.path).is_some_and(|u| self.hints.users.iter().any(|w| w.eq_ignore_ascii_case(&u)))
    }

    /// Artefact files on `fs`: by path, and — for deleted/orphan entries whose name or folder
    /// is lost — by file signature.
    pub fn select(&self, fs: &dyn FileSystem) -> Vec<(FileId, ArtifactKind)> {
        fs.entries()
            .iter()
            .enumerate()
            .filter(|(_, e)| e.size > 0 && self.wanted(e))
            .filter_map(|(i, e)| {
                let id = FileId::new(i);
                ArtifactKind::from_path(&e.path).or_else(|| e.is_deleted().then(|| sniff_entry(fs, id)).flatten()).map(|k| (id, k))
            })
            .collect()
    }

    /// Parse every artefact on `fs` plus path-implied IM accounts.
    pub fn extract(&self, fs: &dyn FileSystem) -> ArtifactResults {
        let mut out = ArtifactResults::default();
        for (id, kind) in self.select(fs) {
            let Some(entry) = fs.entry(id) else { continue };
            out.merge(self.extract_one(fs, id, entry, kind));
        }
        for entry in fs.entries().iter().filter(|e| self.wanted(e)) {
            out.merge(im_traces(entry));
        }
        out.tag();
        out
    }

    fn extract_one(&self, fs: &dyn FileSystem, id: FileId, entry: &FileEntry, kind: ArtifactKind) -> ArtifactResults {
        let cap = kind.max_size().min(self.hints.max_file_size);
        let mut buf = vec![0u8; entry.size.min(cap) as usize];
        let mut out = match fs.read(id, 0, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                // Wallet folders are recognised by their path; other parsers want the bare name.
                let hint = if kind == ArtifactKind::WalletDir { &entry.path } else { &entry.name };
                kind.parse(hint, &buf)
            }
            Err(e) => {
                let mut r = ArtifactResults::default();
                r.damage.push(Damage::new(DamageKind::Unreadable, None, format!("{}: {e}", entry.path)));
                r
            }
        };
        if entry.size > cap {
            out.damage.push(Damage::truncated(format!("{}: {} bytes, parsed first {cap}", entry.path, entry.size)));
        }
        if entry.is_deleted() && !entry.damage.is_empty() {
            out.damage.push(Damage::new(DamageKind::Missing, None, format!("{}: deleted entry, content may be overwritten", entry.path)));
        }
        if kind == ArtifactKind::Lnk {
            lnk_open_times(entry, &mut out);
        }
        if kind.dated_by_file() {
            let first = entry.times.created.or(entry.times.modified);
            let last = entry.times.modified.or(first);
            for id in out.identities.iter_mut().filter(|i| i.first_seen.is_none()) {
                id.first_seen = first;
                id.last_seen = last;
            }
        }
        out.attach(&entry.path, entry.is_deleted(), profile_of(&entry.path).as_deref());
        out
    }
}

fn sniff_entry(fs: &dyn FileSystem, id: FileId) -> Option<ArtifactKind> {
    let mut head = [0u8; 512];
    let n = fs.read(id, 0, &mut head).ok()?;
    ArtifactKind::sniff_magic(&head[..n])
}

/// A link in Recent is created on first open and rewritten on each later open.
fn lnk_open_times(entry: &FileEntry, out: &mut ArtifactResults) {
    let target = out.events.first().map(|e| e.title().to_string()).unwrap_or_else(|| entry.name.trim_end_matches(".lnk").to_string());
    let mut rec = Recorder::new("windows.lnk");
    rec.dated(entry.times.created, EventKind::DocumentOpened, target.clone(), "first opened (LNK created)");
    if entry.times.modified != entry.times.created {
        rec.dated(entry.times.modified, EventKind::DocumentOpened, target, "last opened (LNK modified)");
    }
    out.merge(rec.finish());
}

/// IM / webmail accounts implied by a file's path, dated by the file's own times.
fn im_traces(entry: &FileEntry) -> ArtifactResults {
    let accounts = ImPaths::accounts(&entry.path);
    let mut rec = Recorder::new("im.path");
    let first = entry.times.created.or(entry.times.modified);
    let last = entry.times.modified.or(first);
    for a in accounts {
        rec.identity(a.kind, &a.value, Some(a.service), first);
        rec.identity(a.kind, &a.value, Some(a.service), last);
        rec.dated(last, EventKind::AccountSeen, a.value.clone(), format!("{} account folder/file", a.service));
    }
    let mut out = rec.finish();
    out.attach(&entry.path, entry.is_deleted(), profile_of(&entry.path).as_deref());
    out
}

#[cfg(test)]
mod tests;
