//! What the checks report: observations with a severity, a plain explanation and the numbers
//! behind it, and the verdict they add up to.

use serde::Serialize;
use strata_kernel::Timestamp;

/// How much an observation should worry the examiner. Ordered from least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    /// Context worth knowing (format date, last activity).
    Info,
    /// Unusual but often innocent.
    Notice,
    /// Data is probably missing.
    Warning,
    /// What Strata shows for this disk cannot be trusted as complete.
    Alert,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Alert => "alert",
        }
    }
}

/// Which check made an observation (stable names for tools and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    NotIndexed,
    UnreadVolume,
    UnknownFileSystem,
    SparseFileTable,
    MissingFileRecords,
    MostlyEmpty,
    DeletedMajority,
    Orphans,
    Formatted,
    InstalledOverActivity,
    PreviousWindows,
    NoActivity,
    LittleActivity,
    ActivityGap,
    LastActivity,
    EmptyProfile,
    CleaningTool,
    BrowserWithoutHistory,
    FindingsOutsideFiles,
}

/// One number behind an observation, labelled for people (`Volume size`, `320 GB`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Figure {
    pub label: String,
    pub value: String,
}

/// What an observation says about the disk as a whole; the verdict weighs these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bearing {
    None,
    LittleUse,
    /// Wiped, reformatted or reinstalled, when known.
    Wiped(Option<Timestamp>),
    Unreadable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub severity: Severity,
    pub signal: Signal,
    /// The volume it is about, when it is about one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<u32>,
    pub title: String,
    pub explanation: String,
    pub figures: Vec<Figure>,
    #[serde(skip)]
    pub(crate) bearing: Bearing,
}

impl Observation {
    pub(crate) fn new(severity: Severity, signal: Signal, title: impl Into<String>, explanation: impl Into<String>) -> Self {
        Self { severity, signal, volume: None, title: title.into(), explanation: explanation.into(), figures: Vec::new(), bearing: Bearing::None }
    }

    pub(crate) fn on(mut self, volume: u32) -> Self {
        self.volume = Some(volume);
        self
    }

    pub(crate) fn figure(mut self, label: &str, value: impl Into<String>) -> Self {
        self.figures.push(Figure { label: label.into(), value: value.into() });
        self
    }

    pub(crate) fn bearing(mut self, bearing: Bearing) -> Self {
        self.bearing = bearing;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum VerdictKind {
    /// The file index has not run yet: nothing to judge.
    NotAnalysed,
    NormallyUsed,
    LittleUse,
    WipedOrReinstalled,
    /// Strata could not read the file system: what it shows is not what the disk holds.
    Unreadable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub kind: VerdictKind,
    /// `Probably wiped or reinstalled on 2025-03-10`.
    pub headline: String,
    /// When it was wiped, reformatted or reinstalled, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<Timestamp>,
}

/// Whether what Strata extracted from one disk is plausible.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub verdict: Verdict,
    /// Most severe first.
    pub observations: Vec<Observation>,
}

impl Assessment {
    /// Observations at or above `severity`.
    pub fn at_least(&self, severity: Severity) -> impl Iterator<Item = &Observation> {
        self.observations.iter().filter(move |o| o.severity >= severity)
    }

    /// The verdict is not "normally used" or some observation is a warning or worse.
    pub fn needs_attention(&self) -> bool {
        matches!(self.verdict.kind, VerdictKind::LittleUse | VerdictKind::WipedOrReinstalled | VerdictKind::Unreadable)
            || self.at_least(Severity::Warning).next().is_some()
    }
}
