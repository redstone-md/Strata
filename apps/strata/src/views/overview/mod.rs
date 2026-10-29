//! Overview: coverage of every disk as a sector map, then what was found and what is running.
//! Addresses with on-chain history come first when there are any — they matter most — then
//! disks whose evidence looks incomplete.

mod balances;
mod consistency;
mod findings;
mod jobs;

use super::disk_row::DiskRow;
use super::disks::consistency::verdict_badge;
use super::disks::usage::short_range;
use crate::format;
use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{DiskMaps, Section, TextButton, legend, quiet};
use gpui::{
    AnyElement, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window,
    px,
};
use std::collections::HashMap;
use strata_workbench::{Assessment, EvidenceId};
use gpui_component::{h_flex, v_flex};

pub struct Overview {
    session: Entity<Session>,
    maps: Entity<DiskMaps>,
    /// When each disk was in use (`2009-03 – 2013-07`), loaded off the UI thread.
    usage: HashMap<EvidenceId, SharedString>,
    /// Evidence consistency of each disk, loaded with the usage.
    assessments: HashMap<EvidenceId, Assessment>,
    loads: u64,
    was_active: bool,
    known_disks: usize,
    _observe: Subscription,
}

impl EventEmitter<Navigate> for Overview {}
impl EventEmitter<crate::nav::Jump> for Overview {}

impl Overview {
    pub fn new(session: Entity<Session>, maps: Entity<DiskMaps>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&session, |this, _, cx| this.on_session_changed(cx));
        let mut this = Self { session, maps, usage: HashMap::new(), assessments: HashMap::new(), loads: 0, was_active: false, known_disks: 0, _observe: observe };
        this.load_usage(cx);
        this
    }

    /// Usage and consistency change only when analysis finishes or disks are added.
    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot();
        let active = snapshot.active_jobs().next().is_some();
        if (self.was_active && !active) || snapshot.disks.len() != self.known_disks {
            self.load_usage(cx);
        }
        self.was_active = active;
        cx.notify();
    }

    fn load_usage(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let wb = session.workbench().clone();
        let ids: Vec<EvidenceId> = session.snapshot().disks.iter().map(|d| d.id()).collect();
        self.known_disks = ids.len();
        self.loads += 1;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let (ranges, assessments) = cx
                .background_executor()
                .spawn(async move {
                    let mut ranges = HashMap::new();
                    let mut assessments = HashMap::new();
                    for id in ids {
                        let Ok(machines) = wb.machines(id) else { continue };
                        if let Ok(a) = wb.consistency_with(id, &machines) {
                            assessments.insert(id, a);
                        }
                        if let Some(range) = short_range(&machines.usage) {
                            ranges.insert(id, SharedString::from(range));
                        }
                    }
                    (ranges, assessments)
                })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.loads == ticket {
                    v.usage = ranges;
                    v.assessments = assessments;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn disks(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let maps = self.maps.read(cx);
        let rows: Vec<AnyElement> = snapshot
            .disks
            .iter()
            .map(|d| {
                let busy = snapshot.active_jobs().any(|j| j.evidence == d.id());
                DiskRow::new(d.clone(), maps.get(d.id()), self.session.clone(), busy)
                    .usage(self.usage.get(&d.id()).cloned())
                    .verdict(self.assessments.get(&d.id()).and_then(verdict_badge))
                    .into_any_element()
            })
            .collect();
        let section = Section::new("Disks").note(format::count(rows.len() as u64, "disk", "disks"));
        if rows.is_empty() {
            let this = cx.entity().downgrade();
            return section
                .child(quiet().child("No disks yet. Add an image (.img, .dd, .001, .rdr) or a physical drive."))
                .child(h_flex().child(TextButton::new("overview-add", "Add disk image or drive").strong().on_click(
                    move |_, _, cx| {
                        let _ = this.update(cx, |_, cx| cx.emit(Navigate::to(Screen::Disks)));
                    },
                )));
        }
        section.aside(legend()).child(v_flex().gap(t.block_gap).children(rows))
    }
}

impl Render for Overview {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let balances = (!snapshot.balances.is_empty()).then(|| balances::section(&snapshot.balances, cx.entity().downgrade()));
        let warnings = consistency::section(&snapshot, &self.assessments, cx);
        v_flex()
            .w_full()
            .max_w(t.content_max_width)
            .gap(t.section_gap)
            .children(balances)
            .children(warnings)
            .child(self.disks(cx))
            .child(
                h_flex()
                    .items_start()
                    .gap(px(56.))
                    .child(findings::section(&snapshot, cx))
                    .child(jobs::section(&snapshot, &self.session)),
            )
    }
}
