//! App shell: backdrop, icon rail, header (title + global search) and the active screen.

use crate::nav::{EXIT_KEY, Screen};
use crate::session::Session;
use crate::theme::tokens;
use crate::views::correlation::CorrelationView;
use crate::views::dashboard::Dashboard;
use crate::views::evidence::EvidenceView;
use crate::views::hits::HitBrowser;
use crate::views::settings::SettingsView;
use crate::views::{accounts, wallets};
use crate::widgets::{Backdrop, IconRail, SearchField};
use gpui::{
    AnyView, AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement,
    Render, StatefulInteractiveElement as _, Styled, Subscription, Window, actions, div, prelude::FluentBuilder as _,
    px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};

actions!(strata, [FocusSearch]);

struct Screens {
    dashboard: Entity<Dashboard>,
    evidence: Entity<EvidenceView>,
    wallets: Entity<HitBrowser>,
    accounts: Entity<HitBrowser>,
    correlation: Entity<CorrelationView>,
    settings: Entity<SettingsView>,
}

impl Screens {
    fn new(session: &Entity<Session>, window: &mut Window, cx: &mut Context<Shell>) -> Self {
        Self {
            dashboard: cx.new(|cx| Dashboard::new(session.clone(), cx)),
            evidence: cx.new(|cx| EvidenceView::new(session.clone(), window, cx)),
            wallets: cx.new(|cx| HitBrowser::new(session.clone(), wallets::config(), window, cx)),
            accounts: cx.new(|cx| HitBrowser::new(session.clone(), accounts::config(), window, cx)),
            correlation: cx.new(|cx| CorrelationView::new(session.clone(), window, cx)),
            settings: cx.new(|cx| SettingsView::new(session.clone(), window, cx)),
        }
    }

    fn view(&self, screen: Screen) -> AnyView {
        match screen {
            Screen::Dashboard => self.dashboard.clone().into(),
            Screen::Evidence => self.evidence.clone().into(),
            Screen::Wallets => self.wallets.clone().into(),
            Screen::Accounts => self.accounts.clone().into(),
            Screen::Correlation => self.correlation.clone().into(),
            Screen::Settings => self.settings.clone().into(),
        }
    }

    fn browser(&self, screen: Screen) -> Option<&Entity<HitBrowser>> {
        match screen {
            Screen::Wallets => Some(&self.wallets),
            Screen::Accounts => Some(&self.accounts),
            _ => None,
        }
    }
}

pub struct Shell {
    session: Entity<Session>,
    screen: Screen,
    search: Entity<InputState>,
    focus: FocusHandle,
    screens: Screens,
    _subscriptions: Vec<Subscription>,
}

impl Shell {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search keys, files, accounts…"));
        let subscriptions = vec![
            cx.subscribe_in(&search, window, |this, _, event: &InputEvent, _, cx| match event {
                InputEvent::Change => this.apply_search(cx),
                InputEvent::PressEnter { .. } if !this.screen.searchable() => this.navigate(Screen::Wallets, cx),
                _ => {}
            }),
        ];
        let focus = cx.focus_handle();
        focus.focus(window, cx);
        let screens = Screens::new(&session, window, cx);
        Self { session, screen: Screen::Dashboard, search, focus, screens, _subscriptions: subscriptions }
    }

    fn search_text(&self, cx: &Context<Self>) -> String {
        self.search.read(cx).value().to_string()
    }

    fn apply_search(&mut self, cx: &mut Context<Self>) {
        let text = self.search_text(cx);
        if let Some(browser) = self.screens.browser(self.screen) {
            browser.update(cx, |b, cx| b.set_search(&text, cx));
        }
    }

    fn navigate(&mut self, screen: Screen, cx: &mut Context<Self>) {
        self.screen = screen;
        match screen {
            Screen::Wallets | Screen::Accounts => self.apply_search(cx),
            Screen::Correlation => self.screens.correlation.update(cx, |c, cx| c.reload(cx)),
            _ => {}
        }
        cx.notify();
    }

    fn rail(&self, cx: &mut Context<Self>) -> IconRail {
        let this = cx.entity().downgrade();
        IconRail::new(self.screen.key(), move |key, _, cx| {
            if key == EXIT_KEY {
                cx.quit();
                return;
            }
            if let Some(screen) = Screen::from_key(key) {
                let _ = this.update(cx, |shell, cx| shell.navigate(screen, cx));
            }
        })
        .group(vec![Screen::Dashboard.rail_item(), Screen::Evidence.rail_item()])
        .group(vec![Screen::Wallets.rail_item(), Screen::Accounts.rail_item(), Screen::Correlation.rail_item()])
        .footer(vec![Screen::Settings.rail_item(), Screen::exit_item()])
    }

    fn header(&self) -> impl IntoElement {
        let t = tokens();
        h_flex()
            .justify_between()
            .items_center()
            .gap(t.gap_lg)
            .child(div().text_size(t.size_title).font_weight(t.light).text_color(t.text).child(self.screen.title()))
            .child(SearchField::new(&self.search).hint("alt+f").width(px(440.)))
    }
}

impl Render for Shell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let error = self.session.read(cx).error().map(str::to_owned);
        let view = self.screens.view(self.screen);
        let content = if self.screen.scrolls() {
            div().id("content").flex_1().min_h_0().overflow_y_scroll().pr_2().child(view).into_any_element()
        } else {
            div().flex_1().min_h_0().flex().flex_col().child(view).into_any_element()
        };
        Backdrop::new().child(
            h_flex()
                .id("shell")
                .track_focus(&self.focus)
                .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                    this.search.update(cx, |s, cx| s.focus(window, cx));
                }))
                .size_full()
                .text_color(t.text)
                .child(self.rail(cx))
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .px(px(36.))
                        .pt(px(28.))
                        .pb(px(24.))
                        .gap(t.gap_lg)
                        .child(self.header())
                        .when_some(error, |el, e| {
                            el.child(div().text_sm().text_color(t.red).child(e))
                        })
                        .child(content),
                ),
        )
    }
}
