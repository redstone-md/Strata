//! The verdict on one group of sightings: which path the traces are about, where the file is
//! now, how sure that is, and why.

use crate::cluster::{Seen, Sighting};
use crate::inputs::EntryState;
use crate::path_key::PathKey;
use crate::trail::{Fate, Verdict};
use strata_leads::fmt::day;

/// Why a place is taken to be the same file as the one the traces name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Basis {
    SamePath,
    SameHash,
    SameContent,
    SameNameSize,
    SameName,
    /// Linked through other copies.
    Related,
}

impl Basis {
    fn confidence(self) -> f32 {
        match self {
            Self::SamePath | Self::SameHash => 0.95,
            Self::SameContent => 0.9,
            Self::SameNameSize => 0.75,
            Self::Related => 0.6,
            Self::SameName => 0.55,
        }
    }

    fn words(self) -> &'static str {
        match self {
            Self::SamePath => "same path",
            Self::SameHash => "same SHA-256",
            Self::SameContent => "same wallet content",
            Self::SameNameSize => "same name and size",
            Self::SameName => "same name",
            Self::Related => "linked through its copies",
        }
    }
}

/// A place the file is now, with its fate and basis.
struct Place<'s> {
    sighting: &'s Sighting<'s>,
    fate: Fate,
    basis: Basis,
}

/// One group of sightings judged as one file.
pub(crate) struct Judged {
    pub origin: PathKey,
    /// The origin as first written by a trace or the file table.
    pub origin_written: String,
    pub verdict: Verdict,
}

fn disk(s: &Sighting<'_>) -> String {
    format!("disk {}", s.evidence().get())
}

fn written(s: &Sighting<'_>) -> String {
    match &s.seen {
        Seen::Reference(r) => r.written.clone(),
        Seen::File(f) => f.path.clone(),
        Seen::Hit(h) => h.file_path.clone().unwrap_or_else(|| format!("disk offset {:#x}", h.offset)),
        Seen::Member(m) => m.member_path.clone(),
        Seen::Attachment(a) => a.name.clone(),
    }
}

impl Judged {
    pub fn judge<'s>(group: &[&'s Sighting<'s>]) -> Self {
        let origin_sighting = Self::origin(group);
        let origin = origin_sighting.key.clone();
        let at_origin = |k: &PathKey| if origin.is_bare() { k.name() == origin.name() } else { *k == origin };
        let origin_like: Vec<&Sighting<'_>> = group.iter().copied().filter(|s| at_origin(&s.key)).collect();
        let mut places: Vec<Place<'_>> = Vec::new();
        for s in group.iter().copied() {
            let here = at_origin(&s.key);
            let basis = if here { if origin.is_bare() { Basis::SameName } else { Basis::SamePath } } else { Self::basis(s, &origin_like) };
            let fate = match &s.seen {
                Seen::Reference(_) => continue,
                Seen::File(f) if here && f.state.is_live() => Fate::Live,
                Seen::File(_) if here => Fate::Deleted { verified: Self::verified(group, &s.key) },
                Seen::File(f) => Fate::Moved { live: f.state.is_live() },
                Seen::Hit(h) if h.is_free() => Fate::Carved,
                // A finding inside a file the table also lists: that file's sighting decides.
                Seen::Hit(_) if group.iter().any(|o| matches!(o.seen, Seen::File(_)) && o.key == s.key) => continue,
                Seen::Hit(h) if h.file_path.as_deref().is_some_and(|p| p.contains("!/")) => Fate::InArchive,
                Seen::Hit(h) => {
                    let live = h.file_state.is_none_or(EntryState::is_live);
                    if here { if live { Fate::Live } else { Fate::Deleted { verified: true } } } else { Fate::Moved { live } }
                }
                Seen::Member(_) => Fate::InArchive,
                Seen::Attachment(_) => Fate::InMail,
            };
            places.push(Place { sighting: s, fate, basis });
        }
        places.sort_by_key(|p| (p.fate.rank(), (p.basis.confidence() * -100.0) as i32));
        let verdict = Self::verdict(group, origin_sighting, &places);
        Self { origin, origin_written: written(origin_sighting), verdict }
    }

    /// The path the trail is about: the earliest full path a trace names, else the oldest
    /// file, else the first place.
    fn origin<'s>(group: &[&'s Sighting<'s>]) -> &'s Sighting<'s> {
        let refs = group.iter().copied().filter(|s| matches!(s.seen, Seen::Reference(_)));
        if let Some(r) = refs.clone().filter(|s| !s.key.is_bare()).min_by_key(|s| s.times().into_iter().min()) {
            return r;
        }
        if let Some(f) = group.iter().copied().filter(|s| matches!(s.seen, Seen::File(_))).min_by_key(|s| (s.times().into_iter().min().is_none(), s.times().into_iter().min())) {
            return f;
        }
        refs.clone().next().unwrap_or(group[0])
    }

    /// Content was read from the entry at `key`: a wallet or key finding sits in it.
    fn verified(group: &[&Sighting<'_>], key: &PathKey) -> bool {
        group.iter().any(|s| matches!(s.seen, Seen::Hit(h) if !h.is_free()) && s.key == *key)
    }

    fn basis(s: &Sighting<'_>, origin: &[&Sighting<'_>]) -> Basis {
        let hash = |x: &Sighting<'_>| if let Seen::File(f) = x.seen { f.sha256.clone().filter(|h| !h.is_empty()) } else { None };
        let content = |x: &Sighting<'_>| if let Seen::Hit(h) = x.seen { h.addresses.iter().cloned().chain(h.fingerprint.clone()).collect() } else { Vec::new() };
        let mine = content(s);
        if hash(s).is_some() && origin.iter().any(|o| hash(o) == hash(s)) {
            Basis::SameHash
        } else if !mine.is_empty() && origin.iter().any(|o| content(o).iter().any(|c| mine.contains(c))) {
            Basis::SameContent
        } else if s.size().is_some() && origin.iter().any(|o| o.name() == s.name() && o.size() == s.size()) {
            Basis::SameNameSize
        } else if origin.iter().any(|o| o.name() == s.name()) {
            Basis::SameName
        } else {
            Basis::Related
        }
    }

    fn verdict(group: &[&Sighting<'_>], origin: &Sighting<'_>, places: &[Place<'_>]) -> Verdict {
        let mut explanation = vec![Self::existence(group, origin)];
        let Some(best) = places.first() else {
            let refs = group.iter().filter(|s| matches!(s.seen, Seen::Reference(_))).count();
            explanation.push("No copy of it was found on any disk of the case.".to_string());
            return Verdict { fate: Fate::NotFound, confidence: (0.5 + 0.1 * refs.min(4) as f32).min(0.9), explanation };
        };
        explanation.push(Self::place_sentence(best, true));
        for p in places.iter().skip(1).take(3) {
            explanation.push(Self::place_sentence(p, false));
        }
        if places.len() > 4 {
            explanation.push(format!("{} more places hold the same file.", places.len() - 4));
        }
        let confidence = match best.fate {
            Fate::Carved if best.basis == Basis::Related || best.basis == Basis::SameName => match best.sighting.seen {
                Seen::Hit(h) => h.confidence.min(0.9),
                _ => 0.6,
            },
            Fate::Carved => 0.85,
            _ => best.basis.confidence(),
        };
        Verdict { fate: best.fate, confidence, explanation }
    }

    /// First sentence: what says the file existed.
    fn existence(group: &[&Sighting<'_>], origin: &Sighting<'_>) -> String {
        let refs: Vec<&Sighting<'_>> = group.iter().copied().filter(|s| matches!(s.seen, Seen::Reference(_))).collect();
        let name = origin.name();
        if refs.is_empty() {
            return match &origin.seen {
                Seen::File(f) => format!("{name} is in the file table of {} at {} ({}).", disk(origin), f.path, f.state.word()),
                Seen::Hit(h) if h.is_free() => format!("{} was found in free space of {}.", h.label, disk(origin)),
                _ => format!("{name} was found at {} on {}.", written(origin), disk(origin)),
            };
        }
        let mut times: Vec<_> = refs.iter().flat_map(|s| s.times()).collect();
        times.sort();
        let span = match (times.first(), times.last()) {
            (Some(a), Some(b)) if day(*a) == day(*b) => format!(" on {}", day(*a)),
            (Some(a), Some(b)) => format!(" between {} and {}", day(*a), day(*b)),
            _ => String::new(),
        };
        let n = refs.len();
        format!("{n} trace{} name{} {}{span}.", if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }, written(origin))
    }

    fn place_sentence(p: &Place<'_>, first: bool) -> String {
        let s = p.sighting;
        let why = p.basis.words();
        let lead = if first { "" } else { "Also: " };
        match (&s.seen, p.fate) {
            (Seen::File(f), Fate::Live) => format!("{lead}It is still there, live on {} volume {}.", disk(s), f.volume),
            (Seen::File(_) | Seen::Hit(_), Fate::Deleted { verified: true }) => {
                format!("{lead}Its entry is deleted on {}, but wallet or key content was still read from it, so it can be recovered.", disk(s))
            }
            (_, Fate::Deleted { .. }) => {
                format!("{lead}Its entry is deleted on {} and no wallet content was read from it; the clusters may have been reused.", disk(s))
            }
            (_, Fate::Moved { live }) => {
                let state = if live { "live" } else { "deleted" };
                format!("{lead}A file with the {why} is at {} on {} ({state}).", written(s), disk(s))
            }
            (Seen::Member(m), _) => {
                let enc = if m.encrypted { ", encrypted" } else { "" };
                format!("{lead}A copy ({why}) is inside the archive {} on {}{enc}.", m.archive_path, disk(s))
            }
            (Seen::Hit(h), Fate::InArchive) => format!("{lead}{} was read inside {} on {} ({why}).", h.label, written(s), disk(s)),
            (Seen::Attachment(a), _) => {
                let when = a.at.map(|t| format!(" on {}", day(t))).unwrap_or_default();
                format!("{lead}A copy ({why}) was attached to the mail \"{}\" from {}{when}.", a.subject, a.sender)
            }
            (Seen::Hit(h), _) => format!("{lead}No file entry is left; {} was found in free space at disk offset {:#x} on {} ({why}).", h.label, h.offset, disk(s)),
            _ => format!("{lead}It is at {} on {}.", written(s), disk(s)),
        }
    }
}
