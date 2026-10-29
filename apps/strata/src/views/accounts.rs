//! Accounts: identities (e-mail, logins) and service URLs, grouped by service.

use super::hits::{BrowserConfig, HitColumn};
use strata_workbench::HitCategory;

pub fn config() -> BrowserConfig {
    BrowserConfig {
        title: "Identities & services",
        subtitle: "identities and service URLs, sorted by service",
        categories: vec![HitCategory::Identity, HitCategory::Url],
        columns: vec![
            HitColumn::Service,
            HitColumn::Value,
            HitColumn::Kind,
            HitColumn::Confidence,
            HitColumn::Disk,
            HitColumn::File,
            HitColumn::Offset,
        ],
        initial_sort: Some(HitColumn::Service),
    }
}
