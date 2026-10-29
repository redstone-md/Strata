//! Bitcoin key material for Strata: key encodings and derivation (`keys`), byte-stream
//! detectors for the scan engine (`detectors`) and wallet file parsers (`wallets`).

pub mod detectors;
pub mod keys;
pub mod wallets;

pub use detectors::{detectors, detectors_with};
pub use keys::bip32::{DerivationPlan, ExtendedKey};
pub use keys::mnemonic::{Bip39Mnemonic, ElectrumSeed};
pub use keys::{Address, AddressSet, Network, PrivateKey, ScriptType, Wif};
