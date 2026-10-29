//! Screens reachable from the icon rail.

use crate::widgets::{Glyph, RailItem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Evidence,
    Wallets,
    Accounts,
    Correlation,
    Settings,
}

/// Rail key of the exit button (not a screen).
pub const EXIT_KEY: usize = 99;

impl Screen {
    const ALL: [Screen; 6] =
        [Self::Dashboard, Self::Evidence, Self::Wallets, Self::Accounts, Self::Correlation, Self::Settings];

    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Evidence => "Evidence",
            Self::Wallets => "Wallets & Keys",
            Self::Accounts => "Accounts",
            Self::Correlation => "Correlation",
            Self::Settings => "Settings",
        }
    }

    fn glyph(self) -> Glyph {
        match self {
            Self::Dashboard => Glyph::LayoutDashboard,
            Self::Evidence => Glyph::HardDrive,
            Self::Wallets => Glyph::Wallet,
            Self::Accounts => Glyph::Users,
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
        matches!(self, Self::Dashboard | Self::Evidence | Self::Settings)
    }

    /// Screens whose list the header search filters.
    pub fn searchable(self) -> bool {
        matches!(self, Self::Wallets | Self::Accounts)
    }

    pub fn rail_item(self) -> RailItem {
        RailItem { key: self.key(), glyph: self.glyph(), label: self.title().into() }
    }

    pub fn exit_item() -> RailItem {
        RailItem { key: EXIT_KEY, glyph: Glyph::LogOut, label: "Exit".into() }
    }
}
