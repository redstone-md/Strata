//! What the Accounts lists show: the section rail (used accounts by section, then the
//! addresses only seen) and the table rows of both lists.

use super::day;
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::Cell;
use gpui::{
    App, ElementId, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _,
    Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{AccountRow, Period, ServiceGroup, Standing, TraceKind};

/// Reasons listed in the table (the detail pane lists all).
const TABLE_REASONS: usize = 3;
pub(super) const RAIL_WIDTH: f32 = 220.;

/// The part of the accounts the table shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Pick {
    /// Every account the owner used.
    All,
    Group(ServiceGroup),
    /// Accounts and addresses only seen in data.
    Seen,
}

pub(super) fn used_columns() -> Vec<(&'static str, f32, Cell)> {
    vec![
        ("Service", 170., Cell::Text),
        ("Account", 230., Cell::Data),
        ("Section", 130., Cell::Text),
        ("Why", 260., Cell::Text),
        ("Strength", 76., Cell::Number),
        ("Password", 76., Cell::Text),
        ("First seen", 96., Cell::Data),
        ("Last seen", 96., Cell::Data),
        ("Disks", 130., Cell::Text),
    ]
}

pub(super) fn seen_columns() -> Vec<(&'static str, f32, Cell)> {
    vec![
        ("Account or address", 260., Cell::Data),
        ("Service", 160., Cell::Text),
        ("Where seen", 220., Cell::Text),
        ("Found", 70., Cell::Number),
        ("First seen", 96., Cell::Data),
        ("Last seen", 96., Cell::Data),
        ("Disks", 130., Cell::Text),
    ]
}

/// `saved password, mail client account` (strongest first).
pub(super) fn reasons_text(reasons: &[TraceKind], max: usize) -> String {
    let mut out: Vec<&str> = reasons.iter().take(max).map(|r| r.label()).collect();
    if reasons.len() > max {
        out.push("…");
    }
    out.join(", ")
}

fn disks(snapshot: &Snapshot, row: &AccountRow) -> String {
    row.disks.iter().map(|e| snapshot.disk_label(*e)).collect::<Vec<_>>().join(", ")
}

/// Used accounts matching the search box and the case period.
pub(super) fn matches(row: &AccountRow, needle: &str, period: Period) -> bool {
    (needle.is_empty() || row.identifier.to_lowercase().contains(needle) || row.service.to_lowercase().contains(needle))
        && period.overlaps(row.first_seen, row.last_seen)
}

pub(super) fn used_row(snapshot: &Snapshot, row: &AccountRow) -> Vec<SharedString> {
    [
        row.service.clone(),
        row.identifier.clone(),
        row.group.label().to_string(),
        reasons_text(&row.reasons, TABLE_REASONS),
        format!("{:.0}%", row.strength * 100.0),
        if row.secret { "saved".to_string() } else { String::new() },
        day(row.first_seen),
        day(row.last_seen),
        disks(snapshot, row),
        row.key.clone(),
    ]
    .into_iter()
    .map(SharedString::from)
    .collect()
}

pub(super) fn seen_row(snapshot: &Snapshot, row: &AccountRow) -> Vec<SharedString> {
    let why = match (row.mention_only, row.standing) {
        (true, Standing::Bulk) => "only in dumps and lists".to_string(),
        (true, _) => "in files or free space".to_string(),
        (false, _) => reasons_text(&row.reasons, TABLE_REASONS),
    };
    let found = if row.mention_only { row.traces } else { row.traces + row.mentions };
    [row.identifier.clone(), row.service.clone(), why, found.to_string(), day(row.first_seen), day(row.last_seen), disks(snapshot, row), row.key.clone()]
        .into_iter()
        .map(SharedString::from)
        .collect()
}

type PickHandler = Rc<dyn Fn(Pick, &mut Window, &mut App)>;

/// The section rail: used accounts per section, then the seen addresses.
#[derive(IntoElement)]
pub(super) struct Rail {
    pick: Pick,
    all: u64,
    groups: Vec<(ServiceGroup, u64)>,
    /// `None` while counting.
    seen: Option<u64>,
    on_pick: PickHandler,
}

impl Rail {
    pub fn new(pick: Pick, all: u64, groups: Vec<(ServiceGroup, u64)>, seen: Option<u64>, on_pick: impl Fn(Pick, &mut Window, &mut App) + 'static) -> Self {
        Self { pick, all, groups, seen, on_pick: Rc::new(on_pick) }
    }

    fn entry(&self, id: impl Into<ElementId>, label: &str, count: Option<u64>, pick: Pick) -> impl IntoElement {
        let t = tokens();
        let on = self.pick == pick;
        let handler = self.on_pick.clone();
        let quiet = count == Some(0) && !on;
        h_flex()
            .id(id.into())
            .h(px(28.))
            .px(px(10.))
            .gap(px(8.))
            .items_center()
            .rounded(t.radius)
            .cursor_pointer()
            .text_size(t.size_body)
            .when(on, |el| el.bg(t.selection))
            .hover(|s| s.bg(t.hover))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .text_color(if on { t.emphasis } else if quiet { t.text_secondary } else { t.text })
                    .child(label.to_string()),
            )
            .child(div().text_color(t.text_secondary).child(count.map_or_else(|| "…".to_string(), |n| n.to_string())))
            .on_click(move |_, w, cx| handler(pick, w, cx))
    }
}

impl RenderOnce for Rail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let caption = |text: &'static str| div().px(px(10.)).pt(px(12.)).pb(px(4.)).text_size(t.size_small).text_color(t.text_secondary).child(text);
        let groups: Vec<_> = self.groups.iter().map(|(g, n)| self.entry(("acc-group", *g as usize), g.label(), Some(*n), Pick::Group(*g))).collect();
        v_flex()
            .w(px(RAIL_WIDTH))
            .flex_shrink_0()
            .h_full()
            .pr(px(12.))
            .border_r_1()
            .border_color(t.rule)
            .child(caption("Used by the owner"))
            .child(self.entry("acc-all", "All sections", Some(self.all), Pick::All))
            .children(groups)
            .child(caption("Not proven to be the owner's"))
            .child(self.entry("acc-seen", "Other addresses seen", self.seen, Pick::Seen))
    }
}
