//! The 44px command bar: case and disk count, search, the running job in words (click it for
//! Tasks), and a 2px progress line along its bottom edge across the whole window.

use crate::format;
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, Field};
use gpui::{
    App, Entity, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, StatefulInteractiveElement as _,
    Styled, Window, div, px, relative,
};
use gpui_component::h_flex;
use gpui_component::input::InputState;

const SEARCH_WIDTH: f32 = 460.;

#[derive(IntoElement)]
pub struct CommandBar {
    case_name: String,
    snapshot: Snapshot,
    search: Entity<InputState>,
    /// The period of interest in words (`All dates`, `2008 – 2013`).
    period: String,
    on_case: ClickHandler,
    on_status: ClickHandler,
    on_period: ClickHandler,
}

impl CommandBar {
    pub fn new(case_name: String, snapshot: Snapshot, search: &Entity<InputState>, on_case: ClickHandler, on_status: ClickHandler) -> Self {
        let none: ClickHandler = std::rc::Rc::new(|_, _, _| {});
        Self { case_name, snapshot, search: search.clone(), period: String::new(), on_case, on_status, on_period: none }
    }

    /// The period button beside the search: its label and what a click does.
    pub fn period(mut self, label: String, on_click: ClickHandler) -> Self {
        self.period = label;
        self.on_period = on_click;
        self
    }

    fn period_button(&self) -> impl IntoElement {
        let t = tokens();
        let on_period = self.on_period.clone();
        let narrowed = self.period != "All dates";
        div()
            .id("period")
            .occlude()
            .cursor_pointer()
            .px(px(10.))
            .py(px(4.))
            .border_1()
            .border_color(if narrowed { t.emphasis } else { t.rule })
            .text_size(t.size_body)
            .text_color(if narrowed { t.emphasis } else { t.text_secondary })
            .hover(|s| s.text_color(t.emphasis))
            .child(self.period.clone())
            .on_click(move |e, w, cx| on_period(e, w, cx))
    }

    fn status(&self) -> impl IntoElement {
        let t = tokens();
        let on_status = self.on_status.clone();
        let line = h_flex()
            .id("job-status")
            .occlude()
            .cursor_pointer()
            .gap(px(14.))
            .justify_end()
            .text_size(t.size_body)
            .text_color(t.text_secondary)
            .hover(|s| s.text_color(t.text))
            .on_click(move |e, w, cx| on_status(e, w, cx));
        let Some(job) = self.snapshot.running_job() else {
            let queued = self.snapshot.active_jobs().count() as u64;
            return line.child(if queued > 0 { format!("{} queued", format::count(queued, "job", "jobs")) } else { "Idle".into() });
        };
        let state = if job.is_paused() { "paused".to_string() } else { format::percent(job.fraction()) };
        line.child(div().text_color(t.text).truncate().child(self.snapshot.job_title(job)))
            .child(div().text_color(t.emphasis).child(state))
            .children(format::job_rate(job))
    }

    fn case(&self) -> impl IntoElement {
        let t = tokens();
        let on_case = self.on_case.clone();
        h_flex()
            .gap(px(8.))
            .min_w_0()
            .text_size(t.size_body)
            .child(
                div()
                    .id("case-name")
                    .occlude()
                    .cursor_pointer()
                    .text_color(t.text)
                    .hover(|s| s.text_color(t.emphasis))
                    .truncate()
                    .child(self.case_name.clone())
                    .on_click(move |e, w, cx| on_case(e, w, cx)),
            )
            .child(div().text_color(t.rule).child("/"))
            .child(div().text_color(t.text_secondary).child(format::count(self.snapshot.disks.len() as u64, "disk", "disks")))
    }
}

impl RenderOnce for CommandBar {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        h_flex()
            .flex_1()
            .min_w_0()
            .h_full()
            .pl(t.gutter)
            .pr(px(16.))
            .gap(px(24.))
            .child(div().flex_1().min_w_0().child(self.case()))
            .child(
                h_flex()
                    .gap(px(8.))
                    .child(div().id("search").occlude().child(Field::new(&self.search).hint("Alt+F").width(px(SEARCH_WIDTH))))
                    .child(self.period_button()),
            )
            .child(div().flex_1().min_w_0().child(self.status()))
    }
}

/// Bottom edge of the bar: the running job's fraction as a 2px white line, or a 1px rule.
pub fn progress_line(fraction: Option<f32>) -> impl IntoElement {
    let t = tokens();
    let line = div().w_full().h(px(2.)).flex_shrink_0();
    match fraction {
        Some(f) => line.bg(t.rule).child(div().h_full().w(relative(f)).bg(t.emphasis)),
        None => line.child(div().w_full().h(px(1.)).bg(t.rule)),
    }
}
