//! Overview: coverage of every disk as a sector map, then what was found and what is running.
//! Addresses with on-chain history come first when there are any — they matter most.

mod balances;
mod findings;
mod jobs;

use super::disk_row::DiskRow;
use crate::format;
use crate::nav::{Navigate, Screen};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{DiskMaps, Section, TextButton, legend, quiet};
use gpui::{
    AnyElement, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, Styled, Subscription, Window, px,
};
use gpui_component::{h_flex, v_flex};

pub struct Overview {
    session: Entity<Session>,
    maps: Entity<DiskMaps>,
    _observe: Subscription,
}

impl EventEmitter<Navigate> for Overview {}

impl Overview {
    pub fn new(session: Entity<Session>, maps: Entity<DiskMaps>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&session, |_, _, cx| cx.notify());
        Self { session, maps, _observe: observe }
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
                DiskRow::new(d.clone(), maps.get(d.id()), self.session.clone(), busy).into_any_element()
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
        let balances = (!snapshot.balances.is_empty()).then(|| balances::section(&snapshot.balances));
        v_flex()
            .w_full()
            .max_w(t.content_max_width)
            .gap(t.section_gap)
            .children(balances)
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
