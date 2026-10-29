//! Links between screens: a lead or account pointing at a day of the timeline, a finding or
//! another account.

use super::Shell;
use crate::nav::{Jump, Navigate, Screen};
use gpui::{Context, Window};

impl Shell {
    pub(super) fn jump(&mut self, jump: &Jump, window: &mut Window, cx: &mut Context<Self>) {
        match jump {
            Jump::Day(at) => {
                self.search.update(cx, |s, cx| s.set_value("", window, cx));
                self.screens.timeline.update(cx, |v, cx| v.show_day(*at, cx));
                self.navigate(Navigate::to(Screen::Timeline), cx);
            }
            Jump::Search { screen, text } => {
                self.search.update(cx, |s, cx| s.set_value(text.clone(), window, cx));
                self.navigate(Navigate::to(*screen), cx);
            }
        }
    }
}
