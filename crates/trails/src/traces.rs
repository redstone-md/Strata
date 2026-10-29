//! Timeline events read as traces: a reference to a wallet-relevant file (a shortcut target,
//! a recent document, a file a program loaded per Prefetch, a download, a Recycle Bin entry)
//! or a use of wallet software (installed, downloaded, ran).

use crate::path_key::PathKey;
use strata_accounts::{Service, ServiceKind};
use strata_crypto::WalletFileName;
use strata_kernel::Timestamp;
use strata_leads::EventRecord;
use strata_timeline::EventKind;

/// What a trace says happened to the file it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefKind {
    Opened,
    Created,
    Modified,
    Accessed,
    Deleted,
    Downloaded,
    /// Loaded by a program (Prefetch file list); the program's file name.
    LoadedBy(String),
}

/// An event that names a wallet-relevant file.
#[derive(Debug, Clone)]
pub(crate) struct Reference<'a> {
    pub record: &'a EventRecord,
    /// The path as the trace wrote it.
    pub written: String,
    pub key: PathKey,
    pub kind: RefKind,
    /// File size the trace recorded (LNK target size, download size).
    pub size: Option<u64>,
    /// Volume serial and label the trace recorded (`406B-1C3C 'DATA'`).
    pub volume: Option<String>,
}

/// What a software event shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UseKind {
    Installed,
    Downloaded,
    Ran,
}

/// Wallet software installed, downloaded or run.
#[derive(Debug, Clone)]
pub(crate) struct SoftwareUse<'a> {
    pub record: &'a EventRecord,
    pub name: String,
    pub kind: UseKind,
}

impl SoftwareUse<'_> {
    pub fn at(&self) -> Timestamp {
        self.record.event.at()
    }
}

/// Filesystem walks date every file; trails read artefacts, not the file table's own times.
fn is_filesystem_artifact(artifact: &str) -> bool {
    artifact == "fs" || artifact.starts_with("fs.")
}

/// `size 46126` (LNK) or `(29798968 bytes)` (download) in an event detail.
fn size_in(detail: &str) -> Option<u64> {
    let number = |s: &str| s.trim_start().split(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse::<u64>().ok());
    if let Some(i) = detail.find("size ") {
        return number(&detail[i + 5..]).filter(|n| *n > 0);
    }
    let i = detail.find(" bytes)")?;
    let start = detail[..i].rfind('(')? + 1;
    detail[start..i].trim().parse().ok().filter(|n| *n > 0)
}

/// `volume 406B-1C3C 'DATA'` in an LNK detail.
fn volume_in(detail: &str) -> Option<String> {
    let rest = &detail[detail.find("volume ")? + 7..];
    let v = rest.split(';').next()?.trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// Wallet software an event names, by the shared service catalogue.
fn software(text: &str) -> Option<String> {
    let file = text.rsplit(['\\', '/']).next().unwrap_or(text);
    let service = Service::classify(text).or_else(|| Service::classify(file))?;
    (service.kind == ServiceKind::WalletSoftware).then(|| service.name.to_string())
}

pub(crate) struct Traces<'a> {
    pub references: Vec<Reference<'a>>,
    pub software: Vec<SoftwareUse<'a>>,
}

impl<'a> Traces<'a> {
    /// Read `events`; `relevant` decides which named paths count (wallet-like names, files
    /// that hold findings).
    pub fn read(events: &'a [EventRecord], relevant: impl Fn(&str, &PathKey) -> bool) -> Self {
        let mut out = Traces { references: Vec::new(), software: Vec::new() };
        for record in events {
            let e = &record.event;
            if is_filesystem_artifact(&e.source().artifact) {
                continue;
            }
            let kind = match e.kind() {
                EventKind::DocumentOpened => Some(RefKind::Opened),
                EventKind::FileCreated => Some(RefKind::Created),
                EventKind::FileModified => Some(RefKind::Modified),
                EventKind::FileAccessed => Some(RefKind::Accessed),
                EventKind::FileDeleted => Some(RefKind::Deleted),
                EventKind::Download => Some(RefKind::Downloaded),
                _ => None,
            };
            if let Some(kind) = kind {
                out.reference(record, e.title(), kind, &relevant);
            }
            if e.kind() == EventKind::ProgramRun {
                let exe = e.title().rsplit(['\\', '/']).next().unwrap_or(e.title()).to_string();
                if let Some((_, files)) = e.detail().split_once("files: ") {
                    for f in files.split("; ") {
                        out.reference(record, f, RefKind::LoadedBy(exe.clone()), &relevant);
                    }
                }
            }
            out.software_use(record);
        }
        out
    }

    fn reference(&mut self, record: &'a EventRecord, path: &str, kind: RefKind, relevant: &impl Fn(&str, &PathKey) -> bool) {
        let path = path.trim();
        let key = PathKey::of(path);
        if path.is_empty() || key.as_str().contains("://") && kind != RefKind::Downloaded || !relevant(path, &key) {
            return;
        }
        let detail = record.event.detail();
        self.references.push(Reference { record, written: path.to_string(), key, kind, size: size_in(detail), volume: volume_in(detail) });
    }

    fn software_use(&mut self, record: &'a EventRecord) {
        let e = &record.event;
        let kind = match e.kind() {
            EventKind::ProgramInstalled => UseKind::Installed,
            EventKind::Download => UseKind::Downloaded,
            EventKind::ProgramRun | EventKind::WalletActivity => UseKind::Ran,
            _ => return,
        };
        let name = software(e.title()).or_else(|| {
            // Installs the catalogue does not know (`Bitcoin 0.3.21`) keep their own name when tagged.
            (kind == UseKind::Installed && e.is_crypto()).then(|| e.title().trim().to_string())
        });
        if let Some(name) = name {
            self.software.push(SoftwareUse { record, name, kind });
        }
    }
}

/// Default relevance: the name says wallet.
pub(crate) fn wallet_named(path: &str) -> bool {
    WalletFileName::classify(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_kernel::EvidenceId;
    use strata_timeline::{EventSource, TimelineEvent};

    fn rec(kind: EventKind, title: &str, detail: &str, artifact: &str) -> EventRecord {
        let at = Timestamp::from_unix_secs(1_300_000_000).unwrap();
        EventRecord { id: 1, evidence: EvidenceId::new(1), event: TimelineEvent::new(at, kind, title, EventSource::new(artifact, "/x")).with_detail(detail) }
    }

    #[test]
    fn reads_references_and_software() {
        let events = vec![
            rec(EventKind::FileCreated, "C:\\Docs\\wallet.dat", "LNK target times; size 98304; volume 406B-1C3C 'DATA'; machine pc", "windows.lnk"),
            rec(EventKind::ProgramRun, "BITCOIN-QT.EXE", "prefetch v17, hash 1, run count 3; files: \\DEVICE\\HARDDISKVOLUME1\\A\\WALLET.DAT; \\DEVICE\\HARDDISKVOLUME1\\A\\DB.LOG", "windows.prefetch"),
            rec(EventKind::FileCreated, "Docs/wallet.dat", "", "fs"),
            rec(EventKind::Download, "C:\\Downloads\\electrum-1.9.exe", "from http://x/electrum-1.9.exe (1234 bytes)", "chrome.history"),
        ];
        let t = Traces::read(&events, |p, _| wallet_named(p));
        assert_eq!(t.references.len(), 2, "{:?}", t.references.iter().map(|r| &r.written).collect::<Vec<_>>());
        assert_eq!(t.references[0].size, Some(98_304));
        assert_eq!(t.references[0].volume.as_deref(), Some("406B-1C3C 'DATA'"));
        assert_eq!(t.references[1].kind, RefKind::LoadedBy("BITCOIN-QT.EXE".into()));
        assert_eq!(t.references[1].key.as_str(), "a/wallet.dat");
        let names: Vec<(&str, UseKind)> = t.software.iter().map(|s| (s.name.as_str(), s.kind)).collect();
        assert!(names.contains(&("Electrum", UseKind::Downloaded)), "{names:?}");
        assert!(names.iter().any(|(_, k)| *k == UseKind::Ran), "{names:?}");
        assert_eq!(size_in("from http://x (29798968 bytes)"), Some(29_798_968));
    }
}
