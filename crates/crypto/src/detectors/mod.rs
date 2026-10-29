//! Byte-stream detectors run by the scan engine (see `strata_kernel::scan`).

mod address;
mod bdb;
mod context;
mod der;
mod extended;
mod hex;
pub mod keywords;
mod markers;
mod minikey;
mod mnemonic;
mod report;
pub mod text;
mod wif;

pub use address::AddressDetector;
pub use bdb::{BdbDetector, BdbMeta};
pub use context::Context;
pub use der::DerKeyDetector;
pub use extended::ExtendedKeyDetector;
pub use hex::HexKeyDetector;
pub use markers::MarkerDetector;
pub use minikey::{minikey_to_key, MinikeyDetector};
pub use mnemonic::MnemonicDetector;
pub use wif::WifDetector;

use crate::keys::bip32::DerivationPlan;
use strata_kernel::scan::Detector;

/// Every crypto detector with default settings (3 derived addresses per path).
pub fn detectors() -> Vec<Box<dyn Detector>> {
    detectors_with(DerivationPlan::new(3))
}

/// Every crypto detector, deriving `plan.count()` addresses per standard path.
pub fn detectors_with(plan: DerivationPlan) -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(WifDetector::default()),
        Box::new(ExtendedKeyDetector::new(plan)),
        Box::new(DerKeyDetector),
        Box::new(HexKeyDetector::default()),
        Box::new(MinikeyDetector::default()),
        Box::new(MnemonicDetector::new(plan)),
        Box::new(AddressDetector::default()),
        Box::new(BdbDetector),
        Box::new(MarkerDetector),
    ]
}

#[cfg(test)]
mod tests;
