//! What the consistency context reads about one disk: plain rows the application layer fills
//! from the case (file index tallies, a few named files, program titles, browser history
//! counts, finding placement) and from the machines context (installations, user activity).
//! Nothing here touches the evidence itself.

use serde::Serialize;
use strata_kernel::Timestamp;

/// Files (not folders) and their summed sizes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub files: u64,
    pub bytes: u64,
}

impl Tally {
    pub fn new(files: u64, bytes: u64) -> Self {
        Self { files, bytes }
    }

    pub fn add(&mut self, other: Tally) {
        self.files = self.files.saturating_add(other.files);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// State of a file index entry as the case stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    Live,
    Deleted,
    /// Deleted and cut off from its folder.
    Orphan,
}

impl EntryState {
    /// From the stored name (`Allocated`, `Deleted`, `Orphan`); unknown names count as live.
    pub fn parse(stored: &str) -> Self {
        match stored {
            "Deleted" => Self::Deleted,
            "Orphan" => Self::Orphan,
            _ => Self::Live,
        }
    }
}

/// NTFS master file table (`$MFT`) as the file index lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTable {
    /// Size of `$MFT`: every file record the volume ever had room for.
    pub bytes: u64,
    /// When `$MFT` was created, which is when the volume was formatted.
    pub created: Option<Timestamp>,
}

impl FileTable {
    /// NTFS file records are 1 KiB on almost every volume (4 KiB on some 4K-sector disks,
    /// which only makes [`FileTable::records`] an over-estimate).
    const RECORD_BYTES: u64 = 1024;

    /// File records the table has room for (used, deleted and never used).
    pub fn records(&self) -> u64 {
        self.bytes / Self::RECORD_BYTES
    }
}

/// One volume with what the file index holds for it.
#[derive(Debug, Clone)]
pub struct VolumeInputs {
    pub index: u32,
    /// File system as people write it (`NTFS`, `FAT32`).
    pub fs: String,
    /// Strata recognised the file system (and so tried to list it).
    pub recognised: bool,
    pub len: u64,
    /// Found as a deleted partition.
    pub recovered: bool,
    pub live: Tally,
    pub deleted: Tally,
    pub orphan: Tally,
    /// Folder entries of any state.
    pub folders: u64,
    pub file_table: Option<FileTable>,
    /// Entries under `Windows.old`.
    pub previous_windows: u64,
}

impl VolumeInputs {
    /// Every entry the index holds for the volume (files and folders, any state).
    pub fn entries(&self) -> u64 {
        self.live.files + self.deleted.files + self.orphan.files + self.folders
    }
}

/// A user's profile folder (`Users/<name>`, `Documents and Settings/<name>`, `home/<name>`).
#[derive(Debug, Clone)]
pub struct ProfileFolder {
    pub volume: u32,
    pub user: String,
    pub live: Tally,
    pub deleted: Tally,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProgramTrace {
    Installed,
    Ran,
}

/// Program install or run events of one title (aggregated).
#[derive(Debug, Clone)]
pub struct ProgramRow {
    pub title: String,
    pub trace: ProgramTrace,
    pub first: Timestamp,
    pub last: Timestamp,
    pub count: u64,
}

/// A file found by name (see [`crate::catalog::file_stems`]).
#[derive(Debug, Clone)]
pub struct NamedFile {
    pub volume: u32,
    pub path: String,
    pub state: EntryState,
}

impl NamedFile {
    pub fn name(&self) -> &str {
        self.path.rsplit(['/', '\\']).next().unwrap_or(&self.path)
    }
}

/// Browsing-history events stored by one parser (`chrome.history`, `firefox.places`).
#[derive(Debug, Clone)]
pub struct HistoryCount {
    pub artifact: String,
    pub events: u64,
}

/// Where the findings (keys, seeds, addresses, identities...) of a disk lie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct HitPlacement {
    /// Inside live files.
    pub live: u64,
    /// Inside deleted or orphaned file entries.
    pub deleted: u64,
    /// Outside any listed file: free space, slack, unpartitioned or unreadable areas.
    pub free: u64,
}

impl HitPlacement {
    pub fn total(&self) -> u64 {
        self.live + self.deleted + self.free
    }
}

/// A stretch of active use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSpan {
    pub from: Timestamp,
    pub to: Timestamp,
    pub active_days: u32,
}

/// When the disk was in use, from user activity only (logons, program runs, browsing,
/// documents, start-up and shutdown, USB devices, wallet traces).
#[derive(Debug, Clone, Default)]
pub struct Activity {
    pub first_day: Option<Timestamp>,
    pub last_day: Option<Timestamp>,
    pub active_days: u32,
    pub events: u64,
    /// Oldest first.
    pub periods: Vec<ActiveSpan>,
}

impl Activity {
    /// Active days of the periods that ended before `t`.
    pub fn days_before(&self, t: Timestamp) -> u32 {
        self.periods.iter().filter(|p| p.to < t).map(|p| p.active_days).sum()
    }

    /// Active days of the periods that began after `t`.
    pub fn days_after(&self, t: Timestamp) -> u32 {
        self.periods.iter().filter(|p| p.from > t).map(|p| p.active_days).sum()
    }
}

/// One operating-system installation on the disk.
#[derive(Debug, Clone)]
pub struct Installation {
    /// `Microsoft Windows XP` style name.
    pub label: String,
    pub volume: Option<u32>,
    pub installed: Option<Timestamp>,
    /// A previous installation kept by an upgrade or reinstall (`Windows.old`).
    pub previous: bool,
    /// User activity placed on this installation.
    pub activity: Activity,
}

impl Installation {
    /// Windows 10 and 11 move the install date to every feature update.
    pub fn date_moves_on_update(&self) -> bool {
        ["Windows 10", "Windows 11"].iter().any(|w| self.label.contains(w))
    }
}

/// Everything the consistency context reads for one disk.
#[derive(Debug, Clone, Default)]
pub struct DiskInputs {
    pub disk_len: u64,
    /// The file index step finished at least once.
    pub indexed: bool,
    pub volumes: Vec<VolumeInputs>,
    pub profiles: Vec<ProfileFolder>,
    pub programs: Vec<ProgramRow>,
    pub named_files: Vec<NamedFile>,
    pub history: Vec<HistoryCount>,
    pub hits: HitPlacement,
    pub activity: Activity,
    pub installations: Vec<Installation>,
}

impl DiskInputs {
    /// Live files of every volume.
    pub fn live(&self) -> Tally {
        let mut t = Tally::default();
        for v in &self.volumes {
            t.add(v.live);
        }
        t
    }
}
