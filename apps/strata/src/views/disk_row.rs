//! One disk as a row: facts and the single action on the left, its sector map on the right.
//! Shared by Overview and Disks.

use crate::format;
use crate::session::{DiskSummary, Session};
use crate::theme::tokens;
use crate::widgets::{Badge, SectorMapView, TextButton, quiet};
use gpui::{App, Entity, IntoElement, ParentElement, RenderOnce, SharedString, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};

const FACTS_WIDTH: f32 = 220.;

#[derive(IntoElement)]
pub struct DiskRow {
    disk: DiskSummary,
    map: Option<Entity<SectorMapView>>,
    session: Entity<Session>,
    busy: bool,
    /// When the disk was in use (`2009-03 – 2013-07`), once known.
    usage: Option<SharedString>,
    /// Evidence consistency verdict, once known.
    verdict: Option<Badge>,
}

impl DiskRow {
    pub fn new(disk: DiskSummary, map: Option<Entity<SectorMapView>>, session: Entity<Session>, busy: bool) -> Self {
        Self { disk, map, session, busy, usage: None, verdict: None }
    }

    pub fn usage(mut self, usage: Option<SharedString>) -> Self {
        self.usage = usage;
        self
    }

    pub fn verdict(mut self, verdict: Option<Badge>) -> Self {
        self.verdict = verdict;
        self
    }

    /// Analyse, Resume or Cancel — whichever applies; nothing once the scan is complete.
    fn action(&self) -> Option<TextButton> {
        let d = &self.disk;
        let id = d.id();
        let session = self.session.clone();
        let button = |label: &'static str| TextButton::new(SharedString::from(format!("disk-action-{id}")), label);
        if self.busy {
            return Some(button("Cancel").on_click(move |_, _, cx| session.update(cx, |s, cx| s.cancel_disk(id, cx))));
        }
        (!d.scan_complete).then(|| {
            button(if d.scanned > 0.0 { "Resume" } else { "Analyse" })
                .strong()
                .on_click(move |_, _, cx| session.update(cx, |s, cx| s.analyse(id, cx)))
        })
    }

    fn facts(&mut self) -> impl IntoElement {
        let t = tokens();
        let d = &self.disk;
        let info = &d.record.info;
        v_flex()
            .w(px(FACTS_WIDTH))
            .flex_shrink_0()
            .gap(px(4.))
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).truncate().child(info.label.clone()))
            .child(quiet().child(format!("{}  {}", format::bytes(info.len), format::source_kind(&format!("{:?}", info.kind)))))
            .child(div().text_size(t.size_body).text_color(t.text).child(format!("{} scanned", format::percent(d.scanned))))
            .children(self.usage.clone().map(|u| quiet().truncate().child(format!("in use {u}"))))
            .children((d.damaged > 0).then(|| h_flex().child(Badge::inverted(format!("{} unreadable", format::bytes(d.damaged))))))
            .children(self.verdict.take().map(|b| h_flex().min_w_0().child(b)))
            .child(h_flex().pt(px(8.)).children(self.action()))
    }
}

impl RenderOnce for DiskRow {
    fn render(mut self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let facts = self.facts();
        h_flex()
            .items_start()
            .gap(px(24.))
            .w_full()
            .child(facts)
            .child(div().flex_1().min_w_0().children(self.map))
    }
}
