//! Screens reachable from the sidebar, and the navigation request views send to the shell.

use crate::widgets::{Glyph, NavItem};
use strata_workbench::{EvidenceId, HitCategory};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Disks,
    Files,
    Search,
    Wallets,
    Accounts,
    Leads,
    Connections,
    Timeline,
    Mail,
    Browser,
    Correlation,
    Tasks,
    Settings,
}

/// Emitted by a view that wants the shell to show another screen, optionally filtered.
#[derive(Debug, Clone, Copy)]
pub struct Navigate {
    pub screen: Screen,
    pub category: Option<HitCategory>,
    /// Volume to open on the Files screen.
    pub volume: Option<(EvidenceId, u32)>,
}

impl Navigate {
    pub fn to(screen: Screen) -> Self {
        Self { screen, category: None, volume: None }
    }

    pub fn files(evidence: EvidenceId, volume: u32) -> Self {
        Self { screen: Screen::Files, category: None, volume: Some((evidence, volume)) }
    }
}

/// Emitted by a view that links to something on another screen.
#[derive(Debug, Clone)]
pub enum Jump {
    /// The timeline, narrowed to the day of this time.
    Day(strata_workbench::Timestamp),
    /// Another screen with the command-bar search set to `text`.
    Search { screen: Screen, text: String },
    /// The connection map, centred on an entity.
    Connections(ConnectTo),
    /// The Files screen on one volume, listing the entries with this name.
    File { evidence: EvidenceId, volume: u32, name: String },
}

/// What the connection map centres on when another screen links to it.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectTo {
    /// A node key (`acct:…`, `lead:…`) or text the map resolves (an address, an e-mail).
    Entity(String),
    /// A stored finding: the node it became, else its value.
    Finding { hit: i64, value: String },
}

impl Screen {
    const ALL: [Screen; 14] = [
        Self::Overview,
        Self::Disks,
        Self::Files,
        Self::Search,
        Self::Wallets,
        Self::Accounts,
        Self::Leads,
        Self::Connections,
        Self::Timeline,
        Self::Mail,
        Self::Browser,
        Self::Correlation,
        Self::Tasks,
        Self::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Disks => "Disks",
            Self::Files => "Files",
            Self::Search => "Search",
            Self::Wallets => "Keys & wallets",
            Self::Accounts => "Accounts",
            Self::Leads => "Leads",
            Self::Connections => "Connections",
            Self::Timeline => "Timeline",
            Self::Mail => "Mail",
            Self::Browser => "Browser",
            Self::Correlation => "Across disks",
            Self::Tasks => "Tasks",
            Self::Settings => "Settings",
        }
    }

    fn glyph(self) -> Glyph {
        match self {
            Self::Overview => Glyph::LayoutDashboard,
            Self::Disks => Glyph::HardDrive,
            Self::Files => Glyph::FolderTree,
            Self::Search => Glyph::Search,
            Self::Wallets => Glyph::KeyRound,
            Self::Accounts => Glyph::Users,
            Self::Leads => Glyph::Lightbulb,
            Self::Connections => Glyph::Waypoints,
            Self::Timeline => Glyph::Clock,
            Self::Mail => Glyph::Mail,
            Self::Browser => Glyph::Globe,
            Self::Correlation => Glyph::GitCompare,
            Self::Tasks => Glyph::Activity,
            Self::Settings => Glyph::Settings,
        }
    }

    pub fn key(self) -> usize {
        self as usize
    }

    /// Stable name for saved view state.
    pub fn name(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Disks => "disks",
            Self::Files => "files",
            Self::Search => "search",
            Self::Wallets => "wallets",
            Self::Accounts => "accounts",
            Self::Leads => "leads",
            Self::Connections => "connections",
            Self::Timeline => "timeline",
            Self::Mail => "mail",
            Self::Browser => "browser",
            Self::Correlation => "correlation",
            Self::Tasks => "tasks",
            Self::Settings => "settings",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    pub fn from_key(key: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.key() == key)
    }

    /// Long-form screens scroll as a page; table screens fill the window and scroll inside.
    pub fn scrolls(self) -> bool {
        matches!(self, Self::Overview | Self::Disks | Self::Tasks | Self::Settings)
    }

    /// Screens whose list the command-bar search filters.
    pub fn searchable(self) -> bool {
        matches!(self, Self::Wallets | Self::Accounts | Self::Leads | Self::Connections | Self::Timeline | Self::Mail | Self::Browser)
    }

    pub fn nav_item(self) -> NavItem {
        NavItem { key: self.key(), glyph: self.glyph(), label: self.title().into() }
    }

    /// Main navigation, in sidebar order.
    pub fn main() -> Vec<NavItem> {
        Self::ALL.into_iter().filter(|s| *s != Self::Settings).map(Self::nav_item).collect()
    }
}
