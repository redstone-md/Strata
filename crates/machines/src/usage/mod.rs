//! When a disk (or one installation on it) was in use: first and last evidence, periods of
//! active use, monthly activity, typical hours and weekdays. Built only from user activity
//! (logons, program runs, browsing, documents, power events, USB, wallet traces), never from
//! filesystem MACB times, which installs, updates and copies rewrite in bulk.

mod analyzer;

pub use analyzer::UsageAnalyzer;

use crate::values::When;
use serde::Serialize;
use strata_kernel::Timestamp;
use strata_timeline::EventKind;

/// Kind of user activity an event shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum ActivityKind {
    Logon,
    Program,
    Web,
    Document,
    /// Start-up and shutdown records.
    Power,
    /// USB devices plugged in.
    Device,
    Wallet,
}

/// System-log titles (prefixes) that record a start-up or shutdown.
pub const POWER_TITLE_PREFIXES: &[&str] = &[
    "System start",
    "System shutdown",
    "System boot",
    "Unexpected shutdown",
    "EventLog event 6005",
    "EventLog event 6006",
    "EventLog event 6009",
];
/// System-log titles (infixes) that record a user-initiated shutdown or restart.
pub const POWER_TITLE_INFIXES: &[&str] = &[" initiated by "];
/// Logon titles that are not activity of a user at the machine.
pub const NOT_ACTIVITY_PREFIXES: &[&str] = &["Failed "];

impl ActivityKind {
    pub const ALL: [ActivityKind; 7] = [Self::Logon, Self::Program, Self::Web, Self::Document, Self::Power, Self::Device, Self::Wallet];

    pub fn label(self) -> &'static str {
        match self {
            Self::Logon => "logons",
            Self::Program => "programs",
            Self::Web => "web",
            Self::Document => "documents",
            Self::Power => "start-up/shutdown",
            Self::Device => "USB devices",
            Self::Wallet => "wallet",
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    /// Event kinds that are user activity whatever their title.
    pub const EVENT_KINDS: &[EventKind] = &[
        EventKind::Login,
        EventKind::ProgramRun,
        EventKind::UrlVisited,
        EventKind::Download,
        EventKind::Search,
        EventKind::FormInput,
        EventKind::Cookie,
        EventKind::DocumentOpened,
        EventKind::UsbDevice,
        EventKind::WalletActivity,
    ];
    /// Event kinds that are activity only with a power title.
    pub const POWER_KINDS: &[EventKind] = &[EventKind::SystemLog, EventKind::Other];

    /// Activity kind of an event already filtered by title (see [`ActivityKind::of`]).
    pub fn of_kind(kind: EventKind) -> Option<Self> {
        Some(match kind {
            EventKind::Login => Self::Logon,
            EventKind::ProgramRun => Self::Program,
            EventKind::UrlVisited | EventKind::Download | EventKind::Search | EventKind::FormInput | EventKind::Cookie => Self::Web,
            EventKind::DocumentOpened => Self::Document,
            EventKind::UsbDevice => Self::Device,
            EventKind::WalletActivity => Self::Wallet,
            EventKind::SystemLog | EventKind::Other => Self::Power,
            _ => return None,
        })
    }

    /// Activity kind of one event; `None` for events that are not user activity.
    pub fn of(kind: EventKind, title: &str) -> Option<Self> {
        if Self::POWER_KINDS.contains(&kind) {
            let power = POWER_TITLE_PREFIXES.iter().any(|p| title.starts_with(p)) || POWER_TITLE_INFIXES.iter().any(|p| title.contains(p));
            return power.then_some(Self::Power);
        }
        if NOT_ACTIVITY_PREFIXES.iter().any(|p| title.starts_with(p)) {
            return None;
        }
        Self::EVENT_KINDS.contains(&kind).then(|| Self::of_kind(kind)).flatten()
    }
}

/// Activity events of one kind, from one file, in one hour (aggregated by the case query).
#[derive(Debug, Clone)]
pub struct ActivityRow {
    pub volume: Option<u32>,
    pub path: String,
    pub kind: ActivityKind,
    /// Hours since the Unix epoch, UTC.
    pub hour: i64,
    pub count: u64,
}

impl ActivityRow {
    pub fn at(&self) -> Option<Timestamp> {
        Timestamp::from_unix_secs(self.hour.checked_mul(3600)?)
    }
}

/// Dates outside this window are impossible for the disk (before 1995, after the image was
/// made or after today).
#[derive(Debug, Clone, Copy)]
pub struct UsageWindow {
    pub not_before: Option<Timestamp>,
    /// `None`: no upper bound known (the clock of this computer is unusable).
    pub not_after: Option<Timestamp>,
}

impl Default for UsageWindow {
    /// From 1995 on, without an upper bound.
    fn default() -> Self {
        Self { not_before: Timestamp::from_civil(1995, 1, 1, 0, 0, 0), not_after: None }
    }
}

impl UsageWindow {
    /// 1995-01-01 up to `not_after`.
    pub fn until(not_after: Timestamp) -> Self {
        Self { not_after: Some(not_after), ..Self::default() }
    }

    pub fn contains(&self, t: Timestamp) -> bool {
        self.not_before.is_none_or(|b| t >= b) && self.not_after.is_none_or(|a| t <= a)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KindCount {
    pub kind: ActivityKind,
    pub events: u64,
    /// Days with this kind of activity.
    pub days: u32,
}

/// A stretch of days with activity, separated from the next by a long gap.
#[derive(Debug, Clone, Serialize)]
pub struct Period {
    /// First and last active day (local midnight as UTC-like day stamps).
    pub from: When,
    pub to: When,
    pub active_days: u32,
    pub events: u64,
    /// What the activity was, most events first.
    pub kinds: Vec<KindCount>,
}

impl Period {
    /// Calendar days from first to last active day, inclusive.
    pub fn span_days(&self) -> i64 {
        (self.to.0.unix_secs() - self.from.0.unix_secs()) / 86_400 + 1
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MonthActivity {
    pub year: i64,
    pub month: u32,
    pub active_days: u32,
    pub events: u64,
}

/// Activity left out of the in-use range: a few events far from all the rest.
#[derive(Debug, Clone, Serialize)]
pub struct Outlier {
    pub from: When,
    pub to: When,
    pub events: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageReport {
    /// First and last active day of the in-use range (outliers excluded).
    pub first_day: Option<When>,
    pub last_day: Option<When>,
    pub periods: Vec<Period>,
    /// Every month from the first to the last active day, quiet months included.
    pub months: Vec<MonthActivity>,
    pub active_days: u32,
    pub events: u64,
    /// Active days per month over the in-use range.
    pub days_per_month: f32,
    /// Events per hour of the day and per weekday (Monday first), in `clock` time.
    pub hours: [u64; 24],
    pub weekdays: [u64; 7],
    /// Shortest run of hours `[start, end)` holding most activity (wraps past midnight).
    pub typical_hours: Option<(u8, u8)>,
    /// `UTC+03:00` when days and hours are the machine's local time, `UTC` otherwise.
    pub clock: String,
    pub outliers: Vec<Outlier>,
    /// Events with impossible dates (before 1995, after the image or today).
    pub out_of_range: u64,
}

impl UsageReport {
    pub fn is_empty(&self) -> bool {
        self.periods.is_empty()
    }

    /// `2009-03-14 – 2013-07-02`.
    pub fn range_label(&self) -> Option<String> {
        let day = |w: &When| w.0.to_string().chars().take(10).collect::<String>();
        Some(format!("{} – {}", day(self.first_day.as_ref()?), day(self.last_day.as_ref()?)))
    }
}
