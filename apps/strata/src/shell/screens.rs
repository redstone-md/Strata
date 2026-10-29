//! The screen views, created once and kept alive so switching screens keeps their state.

use super::Shell;
use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::views::correlation::CorrelationView;
use crate::views::disks::DisksView;
use crate::views::files::FilesView;
use crate::views::hits::HitBrowser;
use crate::views::overview::Overview;
use crate::views::search::SearchView;
use crate::views::settings::SettingsView;
use crate::views::timeline::TimelineView;
use crate::views::{accounts, wallets};
use crate::widgets::DiskMaps;
use gpui::{AnyView, AppContext as _, Context, Entity, Subscription, Window};

pub struct Screens {
    pub overview: Entity<Overview>,
    pub disks: Entity<DisksView>,
    pub files: Entity<FilesView>,
    pub search: Entity<SearchView>,
    pub wallets: Entity<HitBrowser>,
    pub accounts: Entity<HitBrowser>,
    pub timeline: Entity<TimelineView>,
    pub correlation: Entity<CorrelationView>,
    pub settings: Entity<SettingsView>,
}

impl Screens {
    pub fn new(session: &Entity<Session>, window: &mut Window, cx: &mut Context<Shell>) -> (Self, Vec<Subscription>) {
        let maps = cx.new(|cx| DiskMaps::new(session.clone(), cx));
        let overview = cx.new(|cx| Overview::new(session.clone(), maps.clone(), cx));
        let disks = cx.new(|cx| DisksView::new(session.clone(), maps, window, cx));
        let navigate = vec![
            cx.subscribe(&overview, |shell, _, nav: &Navigate, cx| shell.navigate(*nav, cx)),
            cx.subscribe(&disks, |shell, _, nav: &Navigate, cx| shell.navigate(*nav, cx)),
        ];
        let screens = Self {
            overview,
            disks,
            files: cx.new(|cx| FilesView::new(session.clone(), window, cx)),
            search: cx.new(|cx| SearchView::new(session.clone(), window, cx)),
            wallets: cx.new(|cx| HitBrowser::new(session.clone(), wallets::config(), window, cx)),
            accounts: cx.new(|cx| HitBrowser::new(session.clone(), accounts::config(), window, cx)),
            timeline: cx.new(|cx| TimelineView::new(session.clone(), window, cx)),
            correlation: cx.new(|cx| CorrelationView::new(session.clone(), window, cx)),
            settings: cx.new(|cx| SettingsView::new(session.clone(), window, cx)),
        };
        (screens, navigate)
    }

    pub fn view(&self, screen: Screen) -> AnyView {
        match screen {
            Screen::Overview => self.overview.clone().into(),
            Screen::Disks => self.disks.clone().into(),
            Screen::Files => self.files.clone().into(),
            Screen::Search => self.search.clone().into(),
            Screen::Wallets => self.wallets.clone().into(),
            Screen::Accounts => self.accounts.clone().into(),
            Screen::Timeline => self.timeline.clone().into(),
            Screen::Correlation => self.correlation.clone().into(),
            Screen::Settings => self.settings.clone().into(),
        }
    }

    pub fn browser(&self, screen: Screen) -> Option<&Entity<HitBrowser>> {
        match screen {
            Screen::Wallets => Some(&self.wallets),
            Screen::Accounts => Some(&self.accounts),
            _ => None,
        }
    }
}
