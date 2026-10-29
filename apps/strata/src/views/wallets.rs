//! Wallets & Keys: key material, wallet containers and addresses.

use super::hits::{BrowserConfig, HitColumn};
use strata_workbench::HitCategory;

pub fn config() -> BrowserConfig {
    BrowserConfig {
        title: "Keys & wallets",
        categories: vec![
            HitCategory::PrivateKey,
            HitCategory::ExtendedKey,
            HitCategory::Mnemonic,
            HitCategory::Wallet,
            HitCategory::Address,
        ],
        columns: vec![
            HitColumn::Confidence,
            HitColumn::Kind,
            HitColumn::Value,
            HitColumn::Disk,
            HitColumn::File,
            HitColumn::Offset,
            HitColumn::Details,
        ],
        initial_sort: None,
    }
}
