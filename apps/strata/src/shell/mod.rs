//! App shell: command bar across the top, sidebar on the left, the active screen beside it.

mod command_bar;
mod screens;
mod window_controls;

use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Sidebar, quiet};
use command_bar::{CommandBar, progress_line};
use gpui::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Window, WindowControlArea, actions, div, prelude::FluentBuilder as _, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};
use screens::Screens;
use window_controls::WindowControls;
use std::rc::Rc;

actions!(strata, [FocusSearch]);

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
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search keys, addresses, files, accounts"));
        let (screens, navigate) = Screens::new(&session, window, cx);
        let subscriptions = vec![
            navigate,
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe_in(&search, window, |this, _, event: &InputEvent, _, cx| match event {
                InputEvent::Change => this.apply_search(cx),
                InputEvent::PressEnter { .. } if !this.screen.searchable() => this.navigate(Navigate::to(Screen::Wallets), cx),
                _ => {}
            }),
        ];
        let focus = cx.focus_handle();
        focus.focus(window, cx);
        Self { session, screen: Screen::Overview, search, focus, screens, _subscriptions: subscriptions }
    }

    fn apply_search(&mut self, cx: &mut Context<Self>) {
        let text = self.search.read(cx).value().to_string();
        if let Some(browser) = self.screens.browser(self.screen) {
            browser.update(cx, |b, cx| b.set_search(&text, cx));
        } else if self.screen == Screen::Timeline {
            self.screens.timeline.update(cx, |v, cx| v.set_search(&text, cx));
        }
    }

    pub fn navigate(&mut self, nav: Navigate, cx: &mut Context<Self>) {
        self.screen = nav.screen;
        if let Some(browser) = self.screens.browser(nav.screen).cloned() {
            browser.update(cx, |b, cx| b.show_category(nav.category, cx));
        }
        match nav.screen {
            Screen::Wallets | Screen::Accounts | Screen::Timeline => self.apply_search(cx),
            Screen::Correlation => self.screens.correlation.update(cx, |c, cx| c.reload(cx)),
            _ => {}
        }
        cx.notify();
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> Sidebar {
        let this = cx.entity().downgrade();
        Sidebar::new(self.screen.key(), move |key, _, cx| {
            if let Some(screen) = Screen::from_key(key) {
                let _ = this.update(cx, |shell, cx| shell.navigate(Navigate::to(screen), cx));
            }
        })
        .items(Screen::main())
        .footer(vec![Screen::Settings.nav_item()])
    }

    fn top_row(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let session = self.session.read(cx);
        let this = cx.entity().downgrade();
        let on_case = Rc::new(move |_: &_, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |shell, cx| shell.navigate(Navigate::to(Screen::Overview), cx));
        });
        // The whole bar is the window's caption: drag to move, double-click to maximize.
        // Interactive parts occlude it so they keep their clicks.
        h_flex()
            .id("command-bar")
            .h(t.command_bar_height)
            .flex_shrink_0()
            .window_control_area(WindowControlArea::Drag)
            .child(
                h_flex()
                    .w(t.sidebar_width)
                    .h_full()
                    .flex_shrink_0()
                    .pl(px(20.))
                    .bg(t.sidebar)
                    .text_size(t.size_heading)
                    .font_weight(t.semibold)
                    .text_color(t.emphasis)
                    .child("Strata"),
            )
            .child(CommandBar::new(session.case_name(), session.snapshot().clone(), &self.search, on_case))
            .child(WindowControls)
    }
}

impl Render for Shell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let error = self.session.read(cx).error().map(str::to_owned);
        let progress = progress_line(self.session.read(cx).snapshot().running_job().map(|j| j.fraction()));
        let view = self.screens.view(self.screen);
        let content = if self.screen.scrolls() {
            div().id("content").flex_1().min_h_0().overflow_y_scroll().px(t.gutter).pt(px(28.)).pb(px(48.)).child(view).into_any_element()
        } else {
            div().flex_1().min_h_0().flex().flex_col().pl(t.gutter).pt(px(20.)).child(view).into_any_element()
        };
        v_flex()
            .id("shell")
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                this.search.update(cx, |s, cx| s.focus(window, cx));
            }))
            .size_full()
            .bg(t.ground)
            .font_family(t.font_ui)
            .text_color(t.text)
            .child(self.top_row(cx))
            .child(progress)
            .child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .when_some(error, |el, e| {
                                el.child(div().px(t.gutter).pt(px(16.)).child(quiet().text_color(t.text).child(format!(
                                    "{e}. A temporary case is open instead; pick another case in Settings."
                                ))))
                            })
                            .child(content),
                    ),
            )
    }
}
