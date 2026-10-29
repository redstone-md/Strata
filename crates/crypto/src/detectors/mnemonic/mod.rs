//! Seed phrases in text (UTF-8/ASCII and UTF-16LE): BIP39 in every language, Electrum.

mod phrase;
mod regions;
mod tokenizer;

use super::report::hit;
use crate::keys::bip32::{DerivationPlan, ExtendedKey, KeyVersion};
use crate::keys::{Network, ScriptType};
use phrase::{evaluate, Candidate, PhraseKind};
use regions::RegionFinder;
use serde_json::{json, Value};
use strata_kernel::scan::{Detector, HitCategory, HitSink};
use strata_kernel::Confidence;
use tokenizer::{tokenize_utf16le, tokenize_utf8, Tokenizer};

/// Address derivations (PBKDF2 + EC) allowed per chunk; later phrases are still reported.
const DERIVE_BUDGET: usize = 32;
const MAX_MATCH: usize = 4096;

pub struct MnemonicDetector {
    plan: DerivationPlan,
}

impl Default for MnemonicDetector {
    fn default() -> Self {
        Self::new(DerivationPlan::new(3))
    }
}

impl MnemonicDetector {
    pub fn new(plan: DerivationPlan) -> Self {
        Self { plan }
    }

    fn candidates(chunk: &[u8]) -> Vec<(Candidate, &'static str)> {
        let mut out = Vec::new();
        let mut found = Vec::new();
        for (start, end) in RegionFinder::UTF8.regions(chunk) {
            Self::tokenize(&chunk[start..end], None, &mut found);
            out.extend(found.drain(..).map(|c| (c.shifted(start), "utf-8")));
        }
        for (start, end) in RegionFinder::UTF16LE.regions(chunk) {
            for align in [0, 1] {
                Self::tokenize(&chunk[start..end], Some(align), &mut found);
                out.extend(found.drain(..).map(|c| (c.shifted(start), "utf-16le")));
            }
        }
        out
    }

    fn tokenize(region: &[u8], utf16_align: Option<usize>, found: &mut Vec<Candidate>) {
        let mut on_run = |run: &[tokenizer::Token]| evaluate(run, found);
        let mut tok = Tokenizer::new(&mut on_run);
        match utf16_align {
            None => tokenize_utf8(region, &mut tok),
            Some(align) => tokenize_utf16le(region, align, &mut tok),
        }
    }

    fn confidence(c: &Candidate) -> f32 {
        // Generated phrases rarely repeat words (P(2+ repeats in 12) < 0.1%); prose and
        // well-known test vectors do.
        if c.repeats >= 2 {
            return 0.1;
        }
        match (&c.kind, c.exact) {
            (PhraseKind::Bip39(_), true) if c.words >= 18 => 0.9,
            (PhraseKind::Bip39(_), true) => 0.75,
            (PhraseKind::Bip39(_), false) if c.words >= 18 => 0.6,
            (PhraseKind::Bip39(_), false) => 0.3,
            (PhraseKind::Electrum(s), _) if s.kind() == crate::keys::mnemonic::ElectrumSeedKind::Old => 0.4,
            (PhraseKind::Electrum(_), _) => 0.5,
        }
    }

    fn describe(&self, c: &Candidate, derive: bool) -> (String, String, Value) {
        match &c.kind {
            PhraseKind::Bip39(m) => {
                let mut details = json!({ "type": "bip39", "language": m.language(), "words": m.word_count() });
                if derive {
                    let seed = m.to_seed("");
                    let version = KeyVersion::find(Network::Mainnet, true, ScriptType::P2pkh);
                    if let Some(master) = version.and_then(|v| ExtendedKey::master(&seed, v)) {
                        details["master_xprv"] = json!(master.encode());
                        details["derived"] = self.plan.derive_json(&master);
                    }
                }
                let label = format!("BIP39 mnemonic, {} words ({})", m.word_count(), m.language());
                (label, m.phrase(), details)
            }
            PhraseKind::Electrum(s) => {
                let mut details = json!({ "type": "electrum", "seed_type": s.kind().name(), "words": c.words });
                if derive {
                    details["derived"] = json!(s.addresses("", self.plan.count()));
                }
                (format!("Electrum seed ({})", s.kind().name()), s.phrase().to_string(), details)
            }
        }
    }
}

impl Detector for MnemonicDetector {
    fn id(&self) -> &'static str {
        "crypto.mnemonic"
    }

    fn max_match(&self) -> usize {
        MAX_MATCH
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        for (i, (c, encoding)) in Self::candidates(chunk).into_iter().enumerate() {
            let (label, value, mut details) = self.describe(&c, i < DERIVE_BUDGET);
            details["encoding"] = json!(encoding);
            details["exact_run"] = json!(c.exact);
            sink.emit(
                hit(self.id(), HitCategory::Mnemonic, base, c.start, c.end.saturating_sub(c.start))
                    .confidence(Confidence::new(Self::confidence(&c)))
                    .label(label)
                    .value(value)
                    .details(details),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VOID: &str = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";

    fn scan(data: &[u8]) -> Vec<strata_kernel::scan::Hit> {
        let mut hits = Vec::new();
        MnemonicDetector::default().scan(data, 0, &mut hits);
        hits
    }

    #[test]
    fn finds_phrases_in_text() {
        let text = format!("Wallet backup\n1. {}\n\nnotes: {VOID}.\n", ABANDON.replace(' ', "\n2. "));
        let hits = scan(text.as_bytes());
        let values: Vec<_> = hits.iter().map(|h| h.value.as_str()).collect();
        assert!(values.contains(&ABANDON), "{values:?}");
        assert!(values.contains(&VOID));
        let void = hits.iter().find(|h| h.value == VOID).unwrap();
        assert_eq!(&text.as_bytes()[void.offset as usize..][..4], b"void");
        assert!(void.details["derived"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn utf16_and_case_and_noise() {
        let mut data = vec![0x00, 0xff, 0x13];
        let upper = VOID.to_uppercase();
        data.extend(upper.encode_utf16().flat_map(|u| u.to_le_bytes()));
        let hits = scan(&data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, VOID);
        assert_eq!(hits[0].offset, 3);
        // Invalid checksum: nothing.
        assert!(scan(ABANDON.replace("about", "abandon").as_bytes()).is_empty());
    }

    #[test]
    fn electrum_seeds() {
        let hits = scan(b"seed: cycle rocket west magnet parrot shuffle foot correct salt library feed song\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].details["seed_type"], "standard");
        let hits = scan(b"powerful random nobody notice nothing important anyway look away hidden message over");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].details["seed_type"], "old");
    }

    #[test]
    fn japanese_phrase() {
        let ja = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら";
        let hits = scan(ja.as_bytes());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].details["language"], "japanese");
    }
}
