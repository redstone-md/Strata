//! Where to look for a file the case has not found (or not verified): the drive and volume the
//! traces name, the period it existed in, the program that made it, and wallet-like bytes in
//! free space of the same disks that no trail claims.

use crate::cluster::{Seen, Sighting};
use crate::inputs::WalletHit;
use crate::trail::{Fate, StepKind, TrailStep};
use strata_crypto::WalletNameKind;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::fmt::day;

/// Free-space candidates named per trail.
const MAX_CANDIDATES: usize = 3;
/// A candidate's size may differ from the traced size by this much (databases grow).
const SIZE_SLACK: u64 = 256 * 1024;

pub(crate) struct Hints<'a> {
    /// Free-space wallet findings no standing trail claims.
    pool: &'a [&'a WalletHit],
}

impl<'a> Hints<'a> {
    pub fn new(pool: &'a [&'a WalletHit]) -> Self {
        Self { pool }
    }

    pub fn for_trail(&self, fate: Fate, kind: Option<WalletNameKind>, group: &[&Sighting<'_>], steps: &[TrailStep], disks: &[EvidenceId]) -> Vec<String> {
        if !matches!(fate, Fate::NotFound | Fate::Deleted { verified: false } | Fate::Moved { live: false }) {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(place) = Self::place(group) {
            out.push(place);
        }
        let dated: Vec<Timestamp> = steps.iter().filter(|s| !is_context(s.kind)).filter_map(|s| s.at).collect();
        if let (Some(a), Some(b)) = (dated.iter().min(), dated.iter().max()) {
            let span = if day(*a) == day(*b) { format!("on {}", day(*a)) } else { format!("from {} to {}", day(*a), day(*b)) };
            out.push(format!("It existed {span}; look for files written in that period."));
        }
        if let Some(made) = steps.iter().find(|s| is_context(s.kind)) {
            out.push(format!("It was probably made by the wallet software seen before it: {}.", made.text));
        } else if let Some(k) = kind.filter(|k| k.is_wallet_file()) {
            out.push(format!("Its name says {}.", k.label()));
        }
        if fate == (Fate::Deleted { verified: false }) {
            out.push("Recover the deleted entry from the Files screen and check its bytes; its clusters may belong to another file now.".to_string());
        }
        let size = group.iter().filter_map(|s| s.size()).max();
        let candidates = self.candidates(disks, size);
        if candidates.is_empty() {
            let list: Vec<String> = disks.iter().map(|d| d.get().to_string()).collect();
            out.push(format!("No unclaimed wallet bytes were found in free space of disk {}; carve its free space if that has not been done.", list.join(", ")));
        }
        for h in candidates {
            let about = h.size.map(|s| format!(", about {} KB", s.div_ceil(1024))).unwrap_or_default();
            out.push(format!("Candidate in free space: {} at disk offset {:#x} on disk {}{about}.", h.label, h.offset, h.evidence.get()));
        }
        out
    }

    /// `The traces put it on drive C: (volume 406B-1C3C 'DATA').`
    fn place(group: &[&Sighting<'_>]) -> Option<String> {
        let mut drives: Vec<char> = Vec::new();
        let mut volumes: Vec<&str> = Vec::new();
        for s in group {
            if let Seen::Reference(r) = &s.seen {
                drives.extend(r.key.drive().map(|d| d.to_ascii_uppercase()).filter(|d| !drives.contains(d)));
                if let Some(v) = r.volume.as_deref().filter(|v| !volumes.contains(v)) {
                    volumes.push(v);
                }
            }
        }
        if drives.is_empty() && volumes.is_empty() {
            return None;
        }
        let drives = drives.iter().map(|d| format!("{d}:")).collect::<Vec<_>>().join(", ");
        let volumes = if volumes.is_empty() { String::new() } else { format!(" (volume {})", volumes.join(", ")) };
        let on = if drives.is_empty() { "a volume".to_string() } else { format!("drive {drives}") };
        Some(format!("The traces put it on {on}{volumes}; check which disk of the case held that volume."))
    }

    fn candidates(&self, disks: &[EvidenceId], size: Option<u64>) -> Vec<&'a WalletHit> {
        let fits = |h: &WalletHit| match (size, h.size) {
            (Some(want), Some(got)) => want.abs_diff(got) <= SIZE_SLACK.max(want / 2),
            _ => true,
        };
        let mut found: Vec<&WalletHit> = self.pool.iter().copied().filter(|h| disks.contains(&h.evidence) && fits(h)).collect();
        found.sort_by(|a, b| b.has_records.cmp(&a.has_records).then(b.confidence.total_cmp(&a.confidence)).then(a.offset.cmp(&b.offset)));
        found.truncate(MAX_CANDIDATES);
        found
    }
}

/// Steps about the software, not the file.
pub(crate) fn is_context(kind: StepKind) -> bool {
    matches!(kind, StepKind::Installed | StepKind::Ran)
}
