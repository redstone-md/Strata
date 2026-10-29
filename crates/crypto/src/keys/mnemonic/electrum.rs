//! Electrum seeds: 2.x "Seed version" phrases and 1.x ("old") 12/24-word seeds.

use super::wordlists::WordIndex;
use crate::keys::bip32::{ExtendedKey, KeyVersion, HARDENED};
use crate::keys::address::p2pkh;
use crate::keys::hash::{hash160, hmac_sha512, pbkdf2_sha512, sha256, sha256d};
use crate::keys::{Network, PrivateKey, ScriptType, Wif};
use serde::Serialize;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElectrumSeedKind {
    /// Electrum 1.x, 12 or 24 words from the 1626-word list.
    Old,
    /// 2.x prefix `01`.
    Standard,
    /// 2.x prefix `100`.
    Segwit,
    /// 2.x prefix `101`.
    TwoFactor,
    /// 2.x prefix `102`.
    TwoFactorSegwit,
}

impl ElectrumSeedKind {
    pub fn name(self) -> &'static str {
        match self {
            ElectrumSeedKind::Old => "old",
            ElectrumSeedKind::Standard => "standard",
            ElectrumSeedKind::Segwit => "segwit",
            ElectrumSeedKind::TwoFactor => "2fa",
            ElectrumSeedKind::TwoFactorSegwit => "2fa_segwit",
        }
    }
}

/// One derived address with its private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElectrumAddress {
    pub path: String,
    pub address: String,
    pub wif: String,
}

/// A recognised Electrum seed phrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumSeed {
    kind: ElectrumSeedKind,
    normalized: String,
}

impl ElectrumSeed {
    /// Detect an Electrum seed type, `None` if the phrase is neither old nor 2.x.
    pub fn detect(phrase: &str) -> Option<Self> {
        let normalized = normalize_text(phrase);
        if normalized.is_empty() {
            return None;
        }
        let kind = if old_seed_hex(&normalized).is_some() {
            ElectrumSeedKind::Old
        } else {
            Self::new_seed_kind(&normalized)?
        };
        Some(Self { kind, normalized })
    }

    fn new_seed_kind(normalized: &str) -> Option<ElectrumSeedKind> {
        let h = hmac_sha512(b"Seed version", normalized.as_bytes());
        let words = normalized.split(' ').count();
        match (h[0], h[1] >> 4) {
            (0x01, _) => Some(ElectrumSeedKind::Standard),
            (0x10, 0x0) => Some(ElectrumSeedKind::Segwit),
            (0x10, 0x1) if words == 12 || words >= 20 => Some(ElectrumSeedKind::TwoFactor),
            (0x10, 0x2) => Some(ElectrumSeedKind::TwoFactorSegwit),
            _ => None,
        }
    }

    pub fn kind(&self) -> ElectrumSeedKind {
        self.kind
    }

    pub fn phrase(&self) -> &str {
        &self.normalized
    }

    /// First `count` receive addresses as Electrum derives them.
    pub fn addresses(&self, passphrase: &str, count: u32) -> Vec<ElectrumAddress> {
        match self.kind {
            ElectrumSeedKind::Old => old_seed_hex(&self.normalized)
                .map(|hex| OldElectrum::from_hex_seed(&hex).addresses(count))
                .unwrap_or_default(),
            ElectrumSeedKind::Standard => self.bip32_addresses(passphrase, &[0], ScriptType::P2pkh, count),
            ElectrumSeedKind::Segwit => {
                self.bip32_addresses(passphrase, &[HARDENED, 0], ScriptType::P2wpkh, count)
            }
            // 2FA wallets are 2-of-3 multisig with a TrustedCoin key; no single-key addresses.
            ElectrumSeedKind::TwoFactor | ElectrumSeedKind::TwoFactorSegwit => Vec::new(),
        }
    }

    fn bip32_addresses(&self, passphrase: &str, branch: &[u32], script: ScriptType, count: u32) -> Vec<ElectrumAddress> {
        let salt = format!("electrum{}", normalize_text(passphrase));
        let seed = pbkdf2_sha512(self.normalized.as_bytes(), salt.as_bytes(), 2048);
        let Some(version) = KeyVersion::find(Network::Mainnet, true, ScriptType::P2pkh) else {
            return Vec::new();
        };
        let Some(parent) = ExtendedKey::master(&seed, version).and_then(|m| m.derive_path(branch)) else {
            return Vec::new();
        };
        (0..count)
            .filter_map(|i| {
                let child = parent.derive_child(i)?;
                let key = child.private_key()?;
                let mut path = crate::keys::bip32::format_path(branch);
                path.push_str(&format!("/{i}"));
                Some(ElectrumAddress {
                    path,
                    address: script.address(&child.public_key(), Network::Mainnet),
                    wif: Wif::new(*key, Network::Mainnet, true).encode(),
                })
            })
            .collect()
    }
}

/// Electrum's `normalize_text`: NFKD, lowercase, strip accents, collapse spaces, join CJK.
pub fn normalize_text(text: &str) -> String {
    let lowered: String = text.nfkd().collect::<String>().to_lowercase();
    let stripped: String = lowered.chars().filter(|c| !is_combining_mark(*c)).collect();
    let spaced = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = spaced.chars().collect();
    chars
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            !(c.is_whitespace()
                && *i > 0
                && chars.get(i - 1).is_some_and(|p| is_cjk(*p))
                && chars.get(i + 1).is_some_and(|n| is_cjk(*n)))
        })
        .map(|(_, c)| *c)
        .collect()
}

fn is_cjk(c: char) -> bool {
    const RANGES: &[(u32, u32)] = &[
        (0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x20000, 0x2A6DF), (0x2A700, 0x2B73F),
        (0x2B740, 0x2B81F), (0xF900, 0xFAFF), (0x2F800, 0x2FA1D), (0x3190, 0x319F),
        (0x2E80, 0x2EFF), (0x2F00, 0x2FDF), (0x31C0, 0x31EF), (0x2FF0, 0x2FFF),
        (0xE0100, 0xE01EF), (0x3100, 0x312F), (0x31A0, 0x31BF), (0xFF00, 0xFFEF),
        (0x3040, 0x309F), (0x30A0, 0x30FF), (0x31F0, 0x31FF), (0x1B000, 0x1B0FF),
        (0xAC00, 0xD7AF), (0x1100, 0x11FF), (0xA960, 0xA97F), (0xD7B0, 0xD7FF),
        (0x3130, 0x318F), (0xA4D0, 0xA4FF), (0x16F00, 0x16F9F), (0xA000, 0xA48F),
        (0xA490, 0xA4CF),
    ];
    let n = c as u32;
    RANGES.iter().any(|(lo, hi)| (*lo..=*hi).contains(&n))
}

/// Decode an Electrum 1.x phrase (12 or 24 old-list words) to its hex seed.
pub fn old_seed_hex(normalized: &str) -> Option<String> {
    let index = WordIndex::get();
    let words: Vec<&str> = normalized.split(' ').collect();
    if words.len() != 12 && words.len() != 24 {
        return None;
    }
    let idx: Option<Vec<u16>> = words
        .iter()
        .map(|w| index.lookup(w.as_bytes()).and_then(|e| e.electrum_old_index()))
        .collect();
    old_indices_to_hex(&idx?)
}

/// Electrum `mn_decode` over word indices; `None` when a triple overflows 32 bits.
pub fn old_indices_to_hex(idx: &[u16]) -> Option<String> {
    const N: u64 = 1626;
    let mut out = String::with_capacity(idx.len() / 3 * 8);
    for t in idx.chunks_exact(3) {
        let (w1, w2, w3) = (u64::from(t[0]), u64::from(t[1]), u64::from(t[2]));
        let x = w1 + N * ((w2 + N - w1) % N) + N * N * ((w3 + N - w2) % N);
        if x > u64::from(u32::MAX) {
            return None;
        }
        out.push_str(&format!("{x:08x}"));
    }
    Some(out)
}

/// Electrum 1.x deterministic wallet (stretched seed, sequence-tweaked keys).
pub struct OldElectrum {
    secexp: Option<PrivateKey>,
}

impl OldElectrum {
    pub fn from_hex_seed(hex_seed: &str) -> Self {
        let seed = hex_seed.as_bytes();
        let mut x = seed.to_vec();
        let mut buf = Vec::with_capacity(32 + seed.len());
        for _ in 0..100_000 {
            buf.clear();
            buf.extend_from_slice(&x);
            buf.extend_from_slice(seed);
            x = sha256(&buf).to_vec();
        }
        Self { secexp: PrivateKey::from_slice(&x) }
    }

    /// Master public key: uncompressed point without the `04` prefix (64 bytes).
    pub fn master_public_key(&self) -> Option<[u8; 64]> {
        let pk = self.secexp?.public_key().serialize_uncompressed();
        pk[1..].try_into().ok()
    }

    pub fn addresses(&self, count: u32) -> Vec<ElectrumAddress> {
        let (Some(secexp), Some(mpk)) = (self.secexp, self.master_public_key()) else {
            return Vec::new();
        };
        (0..count)
            .filter_map(|n| {
                let mut msg = format!("{n}:0:").into_bytes();
                msg.extend_from_slice(&mpk);
                let seq = sha256d(&msg);
                let key = secexp.add_tweak(&seq)?;
                let pubkey = key.public_key().serialize_uncompressed();
                let address = p2pkh(&hash160(&pubkey), Network::Mainnet);
                Some(ElectrumAddress {
                    path: format!("m/0/{n}"),
                    address,
                    wif: Wif::new(key, Network::Mainnet, false).encode(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn electrum_standard_vector() {
        let s = ElectrumSeed::detect("cycle rocket west magnet parrot shuffle foot correct salt library feed song").unwrap();
        assert_eq!(s.kind(), ElectrumSeedKind::Standard);
        assert_eq!(s.addresses("", 1)[0].address, "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf");
    }

    #[test]
    fn electrum_segwit_vector() {
        let s = ElectrumSeed::detect("bitter grass shiver impose acquire brush forget axis eager alone wine silver").unwrap();
        assert_eq!(s.kind(), ElectrumSeedKind::Segwit);
        assert_eq!(s.addresses("", 1)[0].address, "bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af");
    }

    #[test]
    fn electrum_old_vector() {
        let s = ElectrumSeed::detect("powerful random nobody notice nothing important anyway look away hidden message over").unwrap();
        assert_eq!(s.kind(), ElectrumSeedKind::Old);
        assert_eq!(s.addresses("", 1)[0].address, "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo");
    }

    #[test]
    fn bip39_phrase_is_not_electrum() {
        let p = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(ElectrumSeed::detect(p).is_none());
        assert!(ElectrumSeed::detect("").is_none());
    }
}
