//! Timeline: what happened on the machines, day by day. Filesystem events are hidden by
//! default — they bury everything else.

mod delegate;
mod strip;

use crate::format;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{TextButton, flat_table};
use delegate::TimelineDelegate;
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, Styled, Subscription, Window, div, px,
};
use gpui_component::table::TableState;
use gpui_component::{h_flex, v_flex};
use strip::{DayRange, DayStrip};

pub struct TimelineView {
    session: Entity<Session>,
    table: Entity<TableState<TimelineDelegate>>,
    strip: DayStrip,
    day: Option<DayRange>,
    generation: u64,
    was_active: bool,
    _observe: Subscription,
}

impl TimelineView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let workbench = session.read(cx).workbench().clone();
        let table = cx.new(|cx| TableState::new(TimelineDelegate::new(workbench), window, cx).col_movable(false));
        let observe = cx.observe(&session, |this, _, cx| this.on_session_changed(cx));
        let generation = session.read(cx).generation();
        let mut this =
            Self { session, table, strip: DayStrip::default(), day: None, generation, was_active: false, _observe: observe };
        this.reload(cx);
        this
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            let wb = session.workbench().clone();
            self.day = None;
            self.table.update(cx, |t, _| t.delegate_mut().set_workbench(wb));
            self.reload(cx);
        } else if self.was_active && !active {
            self.reload(cx);
        }
        self.was_active = active;
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        let text = Some(text.trim().to_string()).filter(|t| !t.is_empty());
        self.table.update(cx, |t, _| t.delegate_mut().query_mut().text = text);
        self.reload(cx);
    }

    fn pick_day(&mut self, day: Option<DayRange>, cx: &mut Context<Self>) {
        self.day = if self.day == day { None } else { day };
        let (from, to) = (self.day.and_then(DayRange::start), self.day.and_then(DayRange::end));
        self.table.update(cx, |t, _| {
            let q = t.delegate_mut().query_mut();
            q.from = from;
            q.to = to;
        });
        self.reload(cx);
    }

    fn toggle_filesystem(&mut self, cx: &mut Context<Self>) {
        self.table.update(cx, |t, _| {
            let q = t.delegate_mut().query_mut();
            q.skip_filesystem = !q.skip_filesystem;
        });
        self.reload(cx);
    }

    fn reload(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let disks = session.snapshot().disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
        self.strip.set_days(session.workbench().events_per_day(None).unwrap_or_default());
        self.table.update(cx, |t, cx| {
            t.delegate_mut().reload(disks);
            t.refresh(cx);
            cx.notify();
        });
        cx.notify();
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let d = self.table.read(cx).delegate();
        let n = d.len() as u64;
        let count = if d.has_more_rows() { format!("first {n}, scroll for more") } else { format::count(n, "event", "events") };
        let fs_label = if d.query().skip_filesystem { "Show filesystem events" } else { "Hide filesystem events" };
        let day = self.day.map(|r| {
            h_flex()
                .gap(px(8.))
                .child(div().text_color(t.text).child(r.label()))
                .child(TextButton::new("all-days", "All days").on_click(cx.listener(|this, _, _, cx| this.pick_day(None, cx))))
        });
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Timeline"))
            .child(div().text_color(t.text_secondary).child(count))
            .children(day)
            .child(div().flex_1())
            .child(TextButton::new("toggle-fs", fs_label).on_click(cx.listener(|this, _, _, cx| this.toggle_filesystem(cx))))
    }
}

impl Render for TimelineView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let this = cx.entity().downgrade();
        let strip = (!self.strip.is_empty()).then(|| {
            self.strip.render(self.day, move |range, cx| {
                let _ = this.update(cx, |v, cx| v.pick_day(Some(range), cx));
            })
        });
        v_flex()
            .size_full()
            .pr(t.gutter)
            .gap(px(16.))
            .child(self.header(cx))
            .children(strip)
            .child(div().flex_1().min_h_0().size_full().child(flat_table(&self.table)))
    }
}
