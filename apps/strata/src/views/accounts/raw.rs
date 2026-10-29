//! Every identity trace and service URL as found (the "All traces" tab of Accounts).

use crate::views::hits::{BrowserConfig, HitColumn};
use strata_workbench::HitCategory;

pub fn config() -> BrowserConfig {
    BrowserConfig {
        title: "All traces",
        categories: vec![HitCategory::Identity, HitCategory::Url],
        columns: vec![
            HitColumn::Service,
            HitColumn::Value,
            HitColumn::Kind,
            HitColumn::Confidence,
            HitColumn::Seen,
            HitColumn::Disk,
            HitColumn::File,
            HitColumn::Offset,
        ],
        initial_sort: Some(HitColumn::Service),
    }
}
