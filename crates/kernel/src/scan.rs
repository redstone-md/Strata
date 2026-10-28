//! Contract between byte-level detectors (crypto, identify, accounts...) and the scan engine.
//!
//! The engine streams every source once in chunks and hands each chunk to every registered
//! [`Detector`]. Detectors are pure: bytes in, [`Hit`]s out.

use crate::Confidence;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HitCategory {
    /// Private key material (WIF, raw scalar, DER, minikey).
    PrivateKey,
    /// BIP32 extended private/public key.
    ExtendedKey,
    /// Seed phrase.
    Mnemonic,
    /// Wallet container (Berkeley DB wallet.dat, Electrum, MultiBit...).
    Wallet,
    /// Cryptocurrency address.
    Address,
    /// Keyword marker (wallet, bitcoin, electrum...).
    Marker,
    /// File signature (start of a carvable file).
    FileSignature,
    /// Identity: e-mail, login, phone.
    Identity,
    /// URL or domain.
    Url,
}

/// One detection at an absolute offset within the scanned source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub detector: String,
    pub category: HitCategory,
    pub offset: u64,
    pub len: u32,
    pub confidence: Confidence,
    /// Short human-readable description, e.g. `WIF compressed mainnet`.
    pub label: String,
    /// The recovered value (key, address, phrase, e-mail). Shown in clear by design.
    pub value: String,
    /// Detector-specific details (derived addresses, encoding, validation notes).
    pub details: serde_json::Value,
}

impl Hit {
    pub fn new(detector: &str, category: HitCategory, offset: u64, len: usize) -> Self {
        Self {
            detector: detector.to_string(),
            category,
            offset,
            len: u32::try_from(len).unwrap_or(u32::MAX),
            confidence: Confidence::MEDIUM,
            label: String::new(),
            value: String::new(),
            details: serde_json::Value::Null,
        }
    }

    pub fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Key used to merge duplicates across overlapping chunks and across evidence.
    pub fn dedup_key(&self) -> (HitCategory, &str) {
        (self.category, self.value.as_str())
    }
}

/// Receives hits from a detector.
pub trait HitSink {
    fn emit(&mut self, hit: Hit);
}

impl HitSink for Vec<Hit> {
    fn emit(&mut self, hit: Hit) {
        self.push(hit);
    }
}

/// A byte-pattern detector run by the single-pass scan engine.
pub trait Detector: Send + Sync {
    /// Stable identifier, e.g. `crypto.wif`.
    fn id(&self) -> &'static str;

    /// Longest match this detector can produce. The engine overlaps consecutive chunks by the
    /// maximum of all detectors' `max_match`, and drops hits that start in the overlap tail so
    /// nothing is reported twice.
    fn max_match(&self) -> usize;

    /// Scan `chunk`, whose first byte sits at absolute offset `base` in the source.
    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink);
}
