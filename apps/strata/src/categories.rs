//! Display names of hit categories and the screen that lists each, defined once.

use crate::nav::Screen;
use strata_workbench::HitCategory;

pub struct CategoryInfo {
    pub category: HitCategory,
    pub label: &'static str,
}

/// Categories surfaced as finding counts, in display order.
pub const FINDINGS: [CategoryInfo; 7] = [
    CategoryInfo { category: HitCategory::PrivateKey, label: "Private keys" },
    CategoryInfo { category: HitCategory::ExtendedKey, label: "Extended keys" },
    CategoryInfo { category: HitCategory::Mnemonic, label: "Seed phrases" },
    CategoryInfo { category: HitCategory::Wallet, label: "Wallet files" },
    CategoryInfo { category: HitCategory::Address, label: "Addresses" },
    CategoryInfo { category: HitCategory::Identity, label: "Identities" },
    CategoryInfo { category: HitCategory::Url, label: "Service URLs" },
];

pub fn label(category: HitCategory) -> &'static str {
    FINDINGS.iter().find(|c| c.category == category).map_or("Other", |c| c.label)
}

/// The table screen that lists a category.
pub fn screen(category: HitCategory) -> Screen {
    match category {
        HitCategory::Identity | HitCategory::Url => Screen::Accounts,
        _ => Screen::Wallets,
    }
}
