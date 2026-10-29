//! The chain of a trail: one dated, clickable step per trace and place, plus the wallet
//! software installed or run before the file first appears.

use crate::cluster::{Seen, Sighting};
use crate::inputs::EntryState;
use crate::traces::{RefKind, SoftwareUse, UseKind};
use crate::trail::{StepKind, StepLink, TrailStep};
use strata_crypto::WalletNameKind;
use strata_kernel::{EvidenceId, Timestamp};
use strata_leads::fmt::day;

/// A modified time this close to the created time says nothing new.
const SAME_MOMENT_SECS: i64 = 60;

/// Plain name of the artefact a trace was read from.
fn source(artifact: &str) -> &str {
    match artifact {
        "windows.lnk" => "shortcut",
        "windows.prefetch" => "Prefetch",
        "registry.shellbags" => "shellbag",
        "registry.ntuser" => "user registry",
        "linux.recently_used" => "recently used list",
        a if a.contains("recycle") => "Recycle Bin",
        a if a.starts_with("chrome.") => "Chrome",
        a if a.starts_with("firefox.") => "Firefox",
        a if a.starts_with("ie.") => "Internet Explorer",
        a if a.starts_with("opera.") => "Opera",
        a => a,
    }
}

fn step(at: Option<Timestamp>, kind: StepKind, text: String, evidence: EvidenceId, link: StepLink) -> TrailStep {
    TrailStep { at, kind, text, evidence, link }
}

/// Steps for the sightings of one file, oldest first, undated last.
pub(crate) fn steps(group: &[&Sighting<'_>]) -> Vec<TrailStep> {
    let mut out = Vec::new();
    for s in group {
        sighting_steps(s, &mut out);
    }
    order(&mut out);
    out
}

fn sighting_steps(s: &Sighting<'_>, out: &mut Vec<TrailStep>) {
    let ev = s.evidence();
    match &s.seen {
        Seen::Reference(r) => {
            let e = &r.record.event;
            let src = source(&e.source().artifact);
            let (kind, text) = match &r.kind {
                RefKind::Opened => (StepKind::Opened, format!("{} opened ({src})", r.written)),
                RefKind::Created => (StepKind::Created, format!("{} created ({src})", r.written)),
                RefKind::Modified => (StepKind::Modified, format!("{} modified ({src})", r.written)),
                RefKind::Accessed => (StepKind::Accessed, format!("{} accessed ({src})", r.written)),
                RefKind::Deleted => (StepKind::Deleted, format!("{} deleted ({src})", r.written)),
                RefKind::Downloaded => (StepKind::Downloaded, format!("{} downloaded ({src})", r.written)),
                RefKind::LoadedBy(exe) => (StepKind::Loaded, format!("{exe} loaded {} ({src})", r.written)),
            };
            out.push(step(Some(e.at()), kind, text, ev, StepLink::Event(r.record.id)));
        }
        Seen::File(f) => {
            let link = || StepLink::File { evidence: f.evidence, volume: Some(f.volume), path: f.path.clone() };
            let place = format!("{} on disk {}", f.path, ev.get());
            if let Some(c) = f.created {
                out.push(step(Some(c), StepKind::Created, format!("{place} created (file table)"), ev, link()));
            }
            if let Some(m) = f.modified.filter(|m| f.created.is_none_or(|c| (m.unix_secs() - c.unix_secs()).abs() > SAME_MOMENT_SECS)) {
                out.push(step(Some(m), StepKind::Modified, format!("{place} last modified (file table)"), ev, link()));
            }
            match f.state {
                EntryState::Live => out.push(step(None, StepKind::Found, format!("{place} is live, {} bytes", f.size), ev, link())),
                state => {
                    let after_write = f.changed.filter(|c| f.modified.is_none_or(|m| *c >= m));
                    let note = if after_write.is_some() { " (last metadata change, close to the deletion)" } else { "" };
                    out.push(step(after_write, StepKind::Deleted, format!("{place} entry is {}{note}", state.word()), ev, link()));
                }
            }
        }
        Seen::Hit(h) => {
            let link = StepLink::Hit { id: h.id, category: h.category, value: h.value.clone() };
            let (kind, text) = match &h.file_path {
                None => (StepKind::Carved, format!("{} at disk offset {:#x} on disk {} (free space)", h.label, h.offset, ev.get())),
                Some(p) => (StepKind::Found, format!("{} read from {p}: {}", h.label, h.value)),
            };
            out.push(step(None, kind, text, ev, link));
        }
        Seen::Member(m) => {
            let link = StepLink::File { evidence: m.evidence, volume: None, path: m.archive_path.clone() };
            let size = m.size.map(|s| format!(", {s} bytes")).unwrap_or_default();
            out.push(step(m.modified, StepKind::Archived, format!("{} inside the archive {}{size}", m.member_path, m.archive_path), ev, link));
        }
        Seen::Attachment(a) => {
            out.push(step(a.at, StepKind::Mailed, format!("{} attached to the mail \"{}\" from {}", a.name, a.subject, a.sender), ev, StepLink::Message { id: a.message, subject: a.subject.clone() }));
        }
    }
}

/// Oldest first; undated steps keep their order after the dated ones.
pub(crate) fn order(steps: &mut [TrailStep]) {
    steps.sort_by_key(|s| (s.at.is_none(), s.at));
}

/// The wallet software that likely made the file: its first install (or download) and first
/// run on the same disks, at or before the file's first dated step.
pub(crate) fn software_steps(uses: &[SoftwareUse<'_>], kind: Option<WalletNameKind>, disks: &[EvidenceId], first: Option<Timestamp>) -> Vec<TrailStep> {
    let word = kind.and_then(WalletNameKind::software_word);
    let related = |u: &&SoftwareUse<'_>| {
        disks.contains(&u.record.evidence)
            && word.is_none_or(|w| u.name.to_lowercase().contains(w))
            && first.is_none_or(|f| u.at().unix_secs() <= f.unix_secs() + 86_400)
    };
    let pick = |want: &[UseKind]| uses.iter().filter(related).filter(|u| want.contains(&u.kind)).min_by_key(|u| u.at());
    let mut out = Vec::new();
    for u in [pick(&[UseKind::Installed, UseKind::Downloaded]), pick(&[UseKind::Ran])].into_iter().flatten() {
        let (kind, verb) = match u.kind {
            UseKind::Installed => (StepKind::Installed, "installed"),
            // Software downloads count as its arrival, not as a step of the file.
            UseKind::Downloaded => (StepKind::Installed, "downloaded"),
            UseKind::Ran => (StepKind::Ran, "ran"),
        };
        let src = source(&u.record.event.source().artifact);
        out.push(step(Some(u.at()), kind, format!("{} {verb} ({src})", u.name), u.record.evidence, StepLink::Event(u.record.id)));
    }
    out
}

/// `2011-05-03 Bitcoin installed` — the step as one line, for text output.
pub fn describe(step: &TrailStep) -> String {
    match step.at {
        Some(t) => format!("{} {}", day(t), step.text),
        None => step.text.clone(),
    }
}
