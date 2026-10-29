//! Screens reachable from the sidebar, and the navigation request views send to the shell.

use crate::widgets::{Glyph, NavItem};
use strata_workbench::HitCategory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Disks,
    Wallets,
    Accounts,
    Timeline,
    Correlation,
    Settings,
}

/// Emitted by a view that wants the shell to show another screen, optionally filtered.
#[derive(Debug, Clone, Copy)]
pub struct Navigate {
    pub screen: Screen,
    pub category: Option<HitCategory>,
}

impl Navigate {
    pub fn to(screen: Screen) -> Self {
        Self { screen, category: None }
    }
}

impl Screen {
    const ALL: [Screen; 7] =
        [Self::Overview, Self::Disks, Self::Wallets, Self::Accounts, Self::Timeline, Self::Correlation, Self::Settings];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Disks => "Disks",
            Self::Wallets => "Keys & wallets",
            Self::Accounts => "Accounts",
            Self::Timeline => "Timeline",
            Self::Correlation => "Across disks",
            Self::Settings => "Settings",
        }
    }

    fn glyph(self) -> Glyph {
        match self {
            Self::Overview => Glyph::LayoutDashboard,
            Self::Disks => Glyph::HardDrive,
            Self::Wallets => Glyph::KeyRound,
            Self::Accounts => Glyph::Users,
            Self::Timeline => Glyph::Clock,
            Self::Correlation => Glyph::GitCompare,
            Self::Settings => Glyph::Settings,
        }
    }

    pub fn key(self) -> usize {
        self as usize
    }

    pub fn from_key(key: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.key() == key)
    }

    /// Long-form screens scroll as a page; table screens fill the window and scroll inside.
    pub fn scrolls(self) -> bool {
        matches!(self, Self::Overview | Self::Disks | Self::Settings)
    }

    /// Screens whose list the command-bar search filters.
    pub fn searchable(self) -> bool {
        matches!(self, Self::Wallets | Self::Accounts | Self::Timeline)
    }

    pub fn nav_item(self) -> NavItem {
        NavItem { key: self.key(), glyph: self.glyph(), label: self.title().into() }
    }

    /// Main navigation, in sidebar order.
    pub fn main() -> Vec<NavItem> {
        Self::ALL.into_iter().filter(|s| *s != Self::Settings).map(Self::nav_item).collect()
    }
}
