//! Column catalogue for hit tables. A browser picks a subset; text, rendering and sorting
//! of each column are defined once here.

use super::details::HitDetails;
use crate::format;
use crate::theme::tokens;
use crate::widgets::{Badge, mono};
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
    /// How many places the value was found.
    Seen,
}

impl HitColumn {
    pub fn column(self) -> Column {
        let (key, name, width) = match self {
            Self::Confidence => ("confidence", "Confidence", 90.),
            Self::Kind => ("kind", "Type", 200.),
            Self::Service => ("service", "Service", 140.),
            Self::Value => ("value", "Value", 360.),
            Self::Disk => ("disk", "Disk", 110.),
            Self::File => ("file", "File", 300.),
            Self::Offset => ("offset", "Offset", 120.),
            Self::Details => ("details", "Details", 280.),
            Self::Seen => ("seen", "Found", 80.),
        };
        let col = Column::new(key, name).width(px(width)).sortable();
        if self.numeric() { col.text_right() } else { col }
    }

    /// Right-aligned columns.
    pub fn numeric(self) -> bool {
        matches!(self, Self::Confidence | Self::Offset | Self::Seen)
    }

    pub fn text(self, h: &StoredHit, disks: &DiskLabels) -> String {
        match self {
            Self::Confidence => format::percent(h.hit.confidence.get()),
            Self::Kind => h.hit.label.clone(),
            Self::Service => HitDetails(&h.hit.details).service().unwrap_or("").to_string(),
            Self::Value => h.hit.value.clone(),
            Self::Disk if h.disks.len() > 1 => format!("{} disks", h.disks.len()),
            Self::Disk => disks.get(&h.evidence).cloned().unwrap_or_else(|| h.evidence.to_string()),
            Self::Seen => format!("{}×", h.occurrences),
            Self::File => h.file_path.clone().unwrap_or_else(|| "unallocated".into()),
            Self::Offset => format::hex_offset(h.hit.offset),
            Self::Details => HitDetails(&h.hit.details).summary(),
        }
    }

    pub fn compare(self, a: &StoredHit, b: &StoredHit, disks: &DiskLabels) -> Ordering {
        match self {
            Self::Confidence => a.hit.confidence.get().total_cmp(&b.hit.confidence.get()),
            Self::Offset => a.hit.offset.cmp(&b.hit.offset),
            Self::Seen => a.occurrences.cmp(&b.occurrences),
            _ => self.text(a, disks).to_lowercase().cmp(&self.text(b, disks).to_lowercase()),
        }
    }

    pub fn render(self, h: &StoredHit, disks: &DiskLabels) -> AnyElement {
        let t = tokens();
        let text = self.text(h, disks);
        let plain = |color| div().w_full().text_size(t.size_body).text_color(color).truncate().child(text.clone());
        match self {
            Self::Confidence => {
                let strong = h.hit.confidence.get() >= 0.8;
                plain(if strong { t.text } else { t.text_secondary }).text_right().into_any_element()
            }
            Self::Value => plain(t.text).font_family(t.font_data).into_any_element(),
            Self::File => {
                let badge = match h.file_state.as_deref() {
                    Some("Deleted") => Some(Badge::outline("deleted")),
                    Some("Orphan") => Some(Badge::outline("orphan")),
                    _ => None,
                };
                let attributed = h.file_path.is_some();
                h_flex()
                    .gap_2()
                    .min_w_0()
                    .children(badge)
                    .child(
                        div()
                            .min_w_0()
                            .text_size(t.size_body)
                            .text_color(if attributed { t.text } else { t.text_secondary })
                            .when(attributed, |el| el.font_family(t.font_data))
                            .truncate()
                            .child(text),
                    )
                    .into_any_element()
            }
            Self::Offset => mono().w_full().text_right().text_size(t.size_body).text_color(t.text_secondary).child(text).into_any_element(),
            Self::Disk | Self::Details => plain(t.text_secondary).into_any_element(),
            Self::Seen => plain(if h.occurrences > 1 { t.text } else { t.text_secondary }).text_right().into_any_element(),
            Self::Kind | Self::Service => plain(t.text).into_any_element(),
        }
    }
}
