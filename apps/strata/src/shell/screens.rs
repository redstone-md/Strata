//! The screen views, created once and kept alive so switching screens keeps their state.

use super::Shell;
use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::views::correlation::CorrelationView;
use crate::views::disks::DisksView;
use crate::views::hits::HitBrowser;
use crate::views::overview::Overview;
use crate::views::settings::SettingsView;
use crate::views::tasks::TasksView;
use crate::views::timeline::TimelineView;
use crate::views::{accounts, wallets};
use crate::widgets::DiskMaps;
use gpui::{AnyView, AppContext as _, Context, Entity, Subscription, Window};

pub struct Screens {
    pub overview: Entity<Overview>,
    pub disks: Entity<DisksView>,
    pub wallets: Entity<HitBrowser>,
    pub accounts: Entity<HitBrowser>,
    pub timeline: Entity<TimelineView>,
    pub correlation: Entity<CorrelationView>,
    pub tasks: Entity<TasksView>,
    pub settings: Entity<SettingsView>,
}

impl Screens {
    pub fn new(session: &Entity<Session>, window: &mut Window, cx: &mut Context<Shell>) -> (Self, Subscription) {
        let maps = cx.new(|cx| DiskMaps::new(session.clone(), cx));
        let overview = cx.new(|cx| Overview::new(session.clone(), maps.clone(), cx));
        let navigate = cx.subscribe(&overview, |shell, _, nav: &Navigate, cx| shell.navigate(*nav, cx));
        let screens = Self {
            overview,
            disks: cx.new(|cx| DisksView::new(session.clone(), maps, window, cx)),
            wallets: cx.new(|cx| HitBrowser::new(session.clone(), wallets::config(), window, cx)),
            accounts: cx.new(|cx| HitBrowser::new(session.clone(), accounts::config(), window, cx)),
            timeline: cx.new(|cx| TimelineView::new(session.clone(), window, cx)),
            correlation: cx.new(|cx| CorrelationView::new(session.clone(), window, cx)),
            tasks: cx.new(|cx| TasksView::new(session.clone(), cx)),
            settings: cx.new(|cx| SettingsView::new(session.clone(), window, cx)),
        };
        (screens, navigate)
    }

    pub fn view(&self, screen: Screen) -> AnyView {
        match screen {
            Screen::Overview => self.overview.clone().into(),
            Screen::Disks => self.disks.clone().into(),
            Screen::Wallets => self.wallets.clone().into(),
            Screen::Accounts => self.accounts.clone().into(),
            Screen::Timeline => self.timeline.clone().into(),
            Screen::Correlation => self.correlation.clone().into(),
            Screen::Tasks => self.tasks.clone().into(),
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
