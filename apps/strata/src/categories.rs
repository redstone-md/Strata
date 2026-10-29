//! Display names and icons of hit categories, defined once for all views.

use crate::widgets::Glyph;
use strata_workbench::HitCategory;

pub struct CategoryInfo {
    pub category: HitCategory,
    pub label: &'static str,
    pub glyph: Glyph,
}

/// Categories surfaced as finding counters, in display order.
pub const FINDINGS: [CategoryInfo; 7] = [
    CategoryInfo { category: HitCategory::PrivateKey, label: "Private keys", glyph: Glyph::KeyRound },
    CategoryInfo { category: HitCategory::ExtendedKey, label: "Extended keys", glyph: Glyph::Shield },
    CategoryInfo { category: HitCategory::Mnemonic, label: "Seeds", glyph: Glyph::FileText },
    CategoryInfo { category: HitCategory::Wallet, label: "Wallets", glyph: Glyph::Wallet },
    CategoryInfo { category: HitCategory::Address, label: "Addresses", glyph: Glyph::Link2 },
    CategoryInfo { category: HitCategory::Identity, label: "Identities", glyph: Glyph::Users },
    CategoryInfo { category: HitCategory::Url, label: "Service URLs", glyph: Glyph::Globe },
];

pub fn label(category: HitCategory) -> &'static str {
    FINDINGS.iter().find(|c| c.category == category).map_or("Other", |c| c.label)
}
