//! Column catalogue for hit tables. A browser picks a subset; text, rendering and sorting
//! of each column are defined once here.

use super::details::HitDetails;
use crate::format;
use crate::theme::tokens;
use crate::widgets::Pill;
use gpui::{AnyElement, IntoElement, ParentElement, Styled, div, prelude::FluentBuilder as _, px};
use gpui_component::h_flex;
use gpui_component::table::Column;
use std::cmp::Ordering;
use std::collections::HashMap;
use strata_workbench::{EvidenceId, StoredHit};

/// Disk id → display label, captured when the table loads.
pub type DiskLabels = HashMap<EvidenceId, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitColumn {
    Confidence,
    Kind,
    Service,
    Value,
    Disk,
    File,
    Offset,
    Details,
}

impl HitColumn {
    pub fn column(self) -> Column {
        let (key, name, width) = match self {
            Self::Confidence => ("confidence", "Conf.", 80.),
            Self::Kind => ("kind", "Type", 150.),
            Self::Service => ("service", "Service", 140.),
            Self::Value => ("value", "Value", 360.),
            Self::Disk => ("disk", "Disk", 110.),
            Self::File => ("file", "File", 300.),
            Self::Offset => ("offset", "Offset", 120.),
            Self::Details => ("details", "Details", 280.),
        };
        let col = Column::new(key, name).width(px(width)).sortable();
        if self == Self::Offset { col.text_right() } else { col }
    }

    pub fn text(self, h: &StoredHit, disks: &DiskLabels) -> String {
        match self {
            Self::Confidence => format::percent(h.hit.confidence.get()),
            Self::Kind => h.hit.label.clone(),
            Self::Service => HitDetails(&h.hit.details).service().unwrap_or("—").to_string(),
            Self::Value => h.hit.value.clone(),
            Self::Disk => disks.get(&h.evidence).cloned().unwrap_or_else(|| h.evidence.to_string()),
            Self::File => h.file_path.clone().unwrap_or_else(|| "unallocated".into()),
            Self::Offset => format::hex_offset(h.hit.offset),
            Self::Details => HitDetails(&h.hit.details).summary(),
        }
    }

    pub fn compare(self, a: &StoredHit, b: &StoredHit, disks: &DiskLabels) -> Ordering {
        match self {
            Self::Confidence => a.hit.confidence.get().total_cmp(&b.hit.confidence.get()),
            Self::Offset => a.hit.offset.cmp(&b.hit.offset),
            _ => self.text(a, disks).to_lowercase().cmp(&self.text(b, disks).to_lowercase()),
        }
    }

    pub fn render(self, h: &StoredHit, disks: &DiskLabels) -> AnyElement {
        let t = tokens();
        let text = self.text(h, disks);
        let plain = |color| div().text_sm().text_color(color).truncate().child(text.clone());
        match self {
            Self::Confidence => {
                let c = h.hit.confidence.get();
                let color = if c >= 0.8 { t.green } else if c >= 0.5 { t.yellow } else { t.orange };
                h_flex()
                    .gap_2()
                    .child(div().size(px(7.)).rounded_full().bg(color))
                    .child(div().text_sm().text_color(t.text).child(text))
                    .into_any_element()
            }
            Self::Value => div().text_sm().font_family("Consolas").text_color(t.text).truncate().child(text).into_any_element(),
            Self::File => {
                let badge = match h.file_state.as_deref() {
                    Some("Deleted") => Some(Pill::new("deleted", t.orange)),
                    Some("Orphan") => Some(Pill::new("orphan", t.yellow)),
                    _ => None,
                };
                let color = if h.file_path.is_some() { t.text } else { t.text_dim };
                h_flex()
                    .gap_2()
                    .min_w_0()
                    .children(badge)
                    .child(div().text_sm().text_color(color).truncate().child(text))
                    .into_any_element()
            }
            Self::Offset => plain(t.text_muted).font_family("Consolas").into_any_element(),
            Self::Disk | Self::Details => plain(t.text_muted).into_any_element(),
            Self::Kind | Self::Service => plain(t.text).when(text == "—", |el| el.text_color(t.text_dim)).into_any_element(),
        }
    }
}
