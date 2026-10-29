//! The profiles strip above the lists: one line per browser profile per disk with what it
//! holds, when it was used and its most visited sites. Selecting a line narrows the lists.

use crate::widgets::{Cell, TextTable};
use gpui::SharedString;
use std::collections::HashMap;
use strata_workbench::{BrowserSegment, EvidenceId, ProfileSummary};

/// Profile lines shown before the strip scrolls.
pub const SHOWN: usize = 5;

pub fn table() -> TextTable {
    TextTable::new(
        vec![
            ("Disk", 110., Cell::Text),
            ("Browser", 120., Cell::Text),
            ("Profile", 220., Cell::Text),
            ("Visits", 70., Cell::Number),
            ("Deleted", 70., Cell::Number),
            ("Searches", 76., Cell::Number),
            ("Downloads", 84., Cell::Number),
            ("Logins & forms", 110., Cell::Number),
            ("Cookies", 70., Cell::Number),
            ("First", 96., Cell::Data),
            ("Last", 96., Cell::Data),
            ("Top sites", 420., Cell::Data),
        ],
        "No browser profiles found yet.",
    )
}

/// Table rows; the hidden last cell is the profile's index in `profiles`.
pub fn rows(profiles: &[ProfileSummary], disks: &HashMap<EvidenceId, String>) -> Vec<Vec<SharedString>> {
    let day = |t: strata_workbench::Timestamp| -> SharedString { t.to_string().chars().take(10).collect::<String>().into() };
    let n = |v: u64| -> SharedString { if v == 0 { SharedString::default() } else { v.to_string().into() } };
    profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let place = match (p.key.user(), p.key.name()) {
                (Some(u), "") => u.to_string(),
                (Some(u), name) => format!("{u} / {name}"),
                (None, name) => name.to_string(),
            };
            let top = p.top_sites.iter().map(|(host, visits)| format!("{host} {visits}")).collect::<Vec<_>>().join(", ");
            vec![
                disks.get(&p.key.evidence).cloned().unwrap_or_else(|| p.key.evidence.to_string()).into(),
                p.key.browser().into(),
                place.into(),
                n(p.count(BrowserSegment::History)),
                n(p.deleted_visits),
                n(p.count(BrowserSegment::Searches)),
                n(p.count(BrowserSegment::Downloads)),
                n(p.count(BrowserSegment::Logins)),
                n(p.count(BrowserSegment::Cookies)),
                p.span.map(|s| day(s.first)).unwrap_or_default(),
                p.span.map(|s| day(s.last)).unwrap_or_default(),
                top.into(),
                i.to_string().into(),
            ]
        })
        .collect()
}
