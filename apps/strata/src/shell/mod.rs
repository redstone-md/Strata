//! App shell: command bar across the top, sidebar on the left, the active screen beside it.

mod command_bar;
mod jump;
mod screens;
mod window_controls;

use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Sidebar, quiet};
use command_bar::{CommandBar, progress_line};
use gpui::{
    AppContext as _, Context, Entity, FocusHandle, InteractiveElement as _, IntoElement, ParentElement, Render,
    StatefulInteractiveElement as _, Styled, Subscription, Task, Window, WindowControlArea, actions, div, prelude::FluentBuilder as _,
    px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};
use crate::view_state::ViewState;
use screens::Screens;
use std::rc::Rc;
use std::time::Duration;
use window_controls::WindowControls;

actions!(strata, [FocusSearch]);

/// Quiet time before a changed view state is written to the case.
const SAVE_DELAY: Duration = Duration::from_millis(800);

pub struct Shell {
    session: Entity<Session>,
    screen: Screen,
    search: Entity<InputState>,
    focus: FocusHandle,
    screens: Screens,
    /// View state last written to the case.
    saved: ViewState,
    _save: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
}

impl Shell {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search keys, addresses, files, accounts"));
        let (screens, screen_subscriptions) = Screens::new(&session, window, cx);
        let watch_views = [
            cx.observe(&screens.wallets, |this, _, cx| this.schedule_save(cx)),
            cx.observe(&screens.accounts, |this, _, cx| this.schedule_save(cx)),
            cx.observe(&screens.timeline, |this, _, cx| this.schedule_save(cx)),
            cx.observe(&screens.tasks, |this, _, cx| this.schedule_save(cx)),
        ];
        let mut subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe_in(&search, window, |this, _, event: &InputEvent, window, cx| match event {
                InputEvent::Change => this.apply_search(cx),
                InputEvent::PressEnter { .. } => this.on_enter(window, cx),
                _ => {}
            }),
        ];
        subscriptions.extend(screen_subscriptions);
        subscriptions.extend(watch_views);
        let focus = cx.focus_handle();
        focus.focus(window, cx);
        Self { session, screen: Screen::Overview, search, focus, screens, saved: ViewState::default(), _save: None, _subscriptions: subscriptions }
    }

    /// What the user is looking at now.
    fn view_state(&self, cx: &gpui::App) -> ViewState {
        let browser = self.screens.browser(self.screen, cx).map(|b| b.read(cx));
        ViewState {
            screen: Some(self.screen.name().to_string()),
            search: self.search.read(cx).value().to_string(),
            category: browser.and_then(|b| b.only()),
            finding: browser.and_then(|b| b.selected_id()),
            day: self.screens.timeline.read(cx).day(),
            task: self.screens.tasks.read(cx).selected().map(|j| j.0),
        }
    }

    /// Write the view state after [`SAVE_DELAY`] of no further changes.
    fn schedule_save(&mut self, cx: &mut Context<Self>) {
        if self.view_state(cx) == self.saved {
            self._save = None;
            return;
        }
        self._save = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(SAVE_DELAY).await;
            let _ = this.update(cx, |shell, cx| shell.save_view_state(cx));
        }));
    }

    /// Write the view state now if it changed (also on close).
    pub fn save_view_state(&mut self, cx: &mut Context<Self>) {
        let state = self.view_state(cx);
        if state != self.saved {
            state.save(self.session.read(cx).workbench());
            self.saved = state;
        }
    }

    /// Bring back the screen, search, filters and selections of the last session.
    pub fn restore(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let state = ViewState::load(self.session.read(cx).workbench());
        if !state.search.is_empty() {
            let text = state.search.clone();
            self.search.update(cx, |s, cx| s.set_value(text, window, cx));
        }
        if let Some((from, to)) = state.day {
            self.screens.timeline.update(cx, |t, cx| t.restore_day((from, to), cx));
        }
        let screen = state.screen.as_deref().and_then(Screen::from_name).unwrap_or(Screen::Overview);
        self.navigate(Navigate { screen, category: state.category, volume: None }, cx);
        if let (Some(id), Some(browser)) = (state.finding, self.screens.browser(screen, cx).cloned()) {
            browser.update(cx, |b, cx| b.select_id(id, cx));
        }
        self.screens.tasks.update(cx, |t, _| t.restore(state.task.map(strata_workbench::JobId)));
        self.saved = state;
    }

    fn apply_search(&mut self, cx: &mut Context<Self>) {
        let text = self.search.read(cx).value().to_string();
        if let Some(browser) = self.screens.browser(self.screen, cx).cloned() {
            browser.update(cx, |b, cx| b.set_search(&text, cx));
        }
        self.screens.search(self.screen, &text, cx);
    }

    /// Enter in the command bar: show the findings that match; when none do, offer the disk
    /// search for the text instead (its button is the first action on the Search screen).
    fn on_enter(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.search.read(cx).value().trim().to_string();
        if !self.screen.searchable() {
            self.navigate(Navigate::to(Screen::Wallets), cx);
        }
        let matches = self.screens.browser(self.screen, cx).map(|b| b.read(cx).result_count(cx));
        if !text.is_empty() && matches == Some(0) {
            self.screens.search.update(cx, |s, cx| s.prefill(&text, window, cx));
            self.navigate(Navigate::to(Screen::Search), cx);
        }
        self.schedule_save(cx);
    }

    pub fn navigate(&mut self, nav: Navigate, cx: &mut Context<Self>) {
        self.screen = nav.screen;
        let tasks = nav.screen == Screen::Tasks;
        self.session.update(cx, |s, cx| s.set_tasks_visible(tasks, cx));
        if let (Screen::Files, Some((evidence, volume))) = (nav.screen, nav.volume) {
            self.screens.files.update(cx, |f, cx| f.open_volume(evidence, volume, cx));
        }
        if let Some(browser) = self.screens.browser(nav.screen, cx).cloned() {
            browser.update(cx, |b, cx| b.show_category(nav.category, cx));
        }
        if nav.screen == Screen::Accounts && nav.category.is_some() {
            self.screens.accounts.update(cx, |v, cx| v.show_traces(cx));
        }
        match nav.screen {
            Screen::Wallets | Screen::Accounts | Screen::Leads | Screen::Timeline => self.apply_search(cx),
            Screen::Correlation => self.screens.correlation.update(cx, |c, cx| c.reload(cx)),
            _ => {}
        }
        self.schedule_save(cx);
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
        let this = cx.entity().downgrade();
        let on_status = Rc::new(move |_: &_, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |shell, cx| shell.navigate(Navigate::to(Screen::Tasks), cx));
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
            .child(CommandBar::new(session.case_name(), session.snapshot().clone(), &self.search, on_case, on_status))
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
