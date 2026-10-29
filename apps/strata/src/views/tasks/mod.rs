//! Tasks: what Strata is doing right now and what it costs — the process's CPU, memory, GPU
//! and disk I/O over the last minutes, every job with its progress and cost, and the selected
//! job's checkpoint, CPU and log.

mod detail;
mod summary;
mod table;

use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::Section;
use gpui::{Context, Entity, EventEmitter, IntoElement, ParentElement, Render, Styled, Subscription, Window};
use gpui_component::v_flex;
use strata_workbench::{JobId, JobView};

/// Emitted when the selected job changes (the shell saves it with the view state).
pub struct SelectionChanged;

pub struct TasksView {
    session: Entity<Session>,
    selected: Option<JobId>,
    _observe: Subscription,
}

impl EventEmitter<SelectionChanged> for TasksView {}

impl TasksView {
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&session, |_, _, cx| cx.notify());
        Self { session, selected: None, _observe: observe }
    }

    pub fn selected(&self) -> Option<JobId> {
        self.selected
    }

    pub fn select(&mut self, id: JobId, cx: &mut Context<Self>) {
        self.selected = Some(id);
        cx.emit(SelectionChanged);
        cx.notify();
    }

    /// Restore a saved selection without announcing it.
    pub fn restore(&mut self, id: Option<JobId>) {
        self.selected = id;
    }

    /// The job the detail shows: the selected one, else the running one, else the newest.
    fn focus<'a>(&self, jobs: &'a [JobView]) -> Option<&'a JobView> {
        self.selected
            .and_then(|id| jobs.iter().find(|j| j.id == id))
            .or_else(|| table::ordered(jobs).into_iter().next())
    }
}

impl Render for TasksView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let session = self.session.read(cx);
        let monitor = session.monitor().clone();
        let snapshot = session.snapshot().clone();
        let jobs = &snapshot.jobs;
        let focus = self.focus(jobs).cloned();
        let lines = focus.as_ref().map(|j| session.job_log(j.id)).unwrap_or_default();
        let active = jobs.iter().filter(|j| j.state.is_active()).count() as u64;
        let note = if active > 0 { crate::format::count(active, "active job", "active jobs") } else { "idle".to_string() };
        let table = table::table(&snapshot, &monitor, focus.as_ref().map(|j| j.id), &self.session, cx);
        v_flex()
            .w_full()
            .max_w(t.content_max_width)
            .gap(t.section_gap)
            .child(Section::new("Strata right now").note("this process").child(summary::row(&monitor)))
            .child(Section::new("Jobs").note(note).child(table))
            .children(focus.map(|j| detail::section(&j, snapshot.job_title(&j), &monitor, &lines)))
    }
}
