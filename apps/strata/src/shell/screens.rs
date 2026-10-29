//! The screen views, created once and kept alive so switching screens keeps their state.

use super::Shell;
use crate::nav::{Jump, Navigate, Screen};
use crate::session::Session;
use crate::views::connections::ConnectionsView;
use crate::views::correlation::CorrelationView;
use crate::views::disks::DisksView;
use crate::views::files::FilesView;
use crate::views::hits::HitBrowser;
use crate::views::overview::Overview;
use crate::views::search::SearchView;
use crate::views::settings::SettingsView;
use crate::views::tasks::TasksView;
use crate::views::timeline::TimelineView;
use crate::views::accounts::AccountsView;
use crate::views::leads::LeadsView;
use crate::views::mail::MailView;
use crate::views::wallets;
use crate::widgets::DiskMaps;
use gpui::{AnyView, AppContext as _, Context, Entity, Subscription, Window};

pub struct Screens {
    pub overview: Entity<Overview>,
    pub disks: Entity<DisksView>,
    pub files: Entity<FilesView>,
    pub search: Entity<SearchView>,
    pub wallets: Entity<HitBrowser>,
    pub accounts: Entity<AccountsView>,
    pub leads: Entity<LeadsView>,
    pub connections: Entity<ConnectionsView>,
    pub timeline: Entity<TimelineView>,
    pub mail: Entity<MailView>,
    pub correlation: Entity<CorrelationView>,
    pub tasks: Entity<TasksView>,
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
            accounts: cx.new(|cx| AccountsView::new(session.clone(), window, cx)),
            leads: cx.new(|cx| LeadsView::new(session.clone(), window, cx)),
            connections: cx.new(|cx| ConnectionsView::new(session.clone(), cx)),
            timeline: cx.new(|cx| TimelineView::new(session.clone(), window, cx)),
            mail: cx.new(|cx| MailView::new(session.clone(), window, cx)),
            correlation: cx.new(|cx| CorrelationView::new(session.clone(), window, cx)),
            tasks: cx.new(|cx| TasksView::new(session.clone(), cx)),
            settings: cx.new(|cx| SettingsView::new(session.clone(), window, cx)),
        };
        let mut subscriptions = navigate;
        subscriptions.extend([
            cx.subscribe_in(&screens.leads, window, |shell, _, jump: &Jump, window, cx| shell.jump(jump, window, cx)),
            cx.subscribe_in(&screens.connections, window, |shell, _, jump: &Jump, window, cx| shell.jump(jump, window, cx)),
            cx.subscribe_in(&screens.accounts, window, |shell, _, jump: &Jump, window, cx| shell.jump(jump, window, cx)),
            cx.subscribe_in(&screens.wallets, window, |shell, _, jump: &Jump, window, cx| shell.jump(jump, window, cx)),
        ]);
        let raw = screens.accounts.read(cx).raw().clone();
        subscriptions.push(cx.subscribe_in(&raw, window, |shell, _, jump: &Jump, window, cx| shell.jump(jump, window, cx)));
        (screens, subscriptions)
    }

    pub fn view(&self, screen: Screen) -> AnyView {
        match screen {
            Screen::Overview => self.overview.clone().into(),
            Screen::Disks => self.disks.clone().into(),
            Screen::Files => self.files.clone().into(),
            Screen::Search => self.search.clone().into(),
            Screen::Wallets => self.wallets.clone().into(),
            Screen::Accounts => self.accounts.clone().into(),
            Screen::Leads => self.leads.clone().into(),
            Screen::Connections => self.connections.clone().into(),
            Screen::Timeline => self.timeline.clone().into(),
            Screen::Mail => self.mail.clone().into(),
            Screen::Correlation => self.correlation.clone().into(),
            Screen::Tasks => self.tasks.clone().into(),
            Screen::Settings => self.settings.clone().into(),
        }
    }

    pub fn browser<'a>(&'a self, screen: Screen, cx: &'a gpui::App) -> Option<&'a Entity<HitBrowser>> {
        match screen {
            Screen::Wallets => Some(&self.wallets),
            Screen::Accounts => Some(self.accounts.read(cx).raw()),
            _ => None,
        }
    }

    /// Apply the command-bar search to a screen's own list (besides its raw-finding browser).
    pub fn search(&self, screen: Screen, text: &str, cx: &mut Context<Shell>) {
        match screen {
            Screen::Accounts => self.accounts.update(cx, |v, cx| v.set_search(text, cx)),
            Screen::Leads => self.leads.update(cx, |v, cx| v.set_search(text, cx)),
            Screen::Connections => self.connections.update(cx, |v, cx| v.set_search(text, cx)),
            Screen::Timeline => self.timeline.update(cx, |v, cx| v.set_search(text, cx)),
            Screen::Mail => self.mail.update(cx, |v, cx| v.set_search(text, cx)),
            _ => {}
        }
    }
}
