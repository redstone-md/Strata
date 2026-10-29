//! Wallet keywords (EN + RU), defined once and compiled for every on-disk encoding:
//! ASCII/UTF-8, CP1251 and UTF-16LE. Used for context scoring and the marker detector.

use super::text::Encoding;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// Clearly about wallets/keys (`wallet.dat`, `privkey`, `приватный ключ`).
    Strong,
    /// Suggestive alone (`key`, `seed`).
    Weak,
}

pub struct Keyword {
    pub text: &'static str,
    pub strength: Strength,
    /// Emitted by the marker detector (others only feed context scoring).
    pub marker: bool,
}

const fn kw(text: &'static str, strength: Strength, marker: bool) -> Keyword {
    Keyword { text, strength, marker }
}

use Strength::{Strong, Weak};

pub static KEYWORDS: &[Keyword] = &[
    kw("bitcoin", Strong, true),
    kw("wallet.dat", Strong, true),
    kw("wallet", Strong, false),
    kw("electrum", Strong, true),
    kw("multibit", Strong, true),
    kw("armory", Strong, true),
    kw("dumpprivkey", Strong, true),
    kw("dumpwallet", Strong, true),
    kw("private key", Strong, true),
    kw("privatekey", Strong, true),
    kw("private_key", Strong, false),
    kw("privkey", Strong, false),
    kw("keypool", Strong, true),
    kw("mkey", Weak, true),
    kw("ckey", Weak, true),
    kw("satoshi", Strong, true),
    kw("blockchain.info", Strong, true),
    kw("seed", Weak, true),
    kw("mnemonic", Strong, true),
    kw("btc-e", Strong, true),
    kw("mtgox", Strong, true),
    kw("bitcointalk", Strong, true),
    kw("secret", Weak, false),
    kw("wif", Weak, false),
    kw("btc", Weak, false),
    kw("key", Weak, false),
    kw("биткоин", Strong, true),
    kw("биткойн", Strong, true),
    kw("кошелёк", Strong, true),
    kw("кошелек", Strong, true),
    kw("кошельк", Strong, false),
    kw("криптовалют", Strong, false),
    kw("криптокошел", Strong, false),
    kw("приватный ключ", Strong, true),
    kw("приватного ключа", Strong, false),
    kw("приватные ключи", Strong, false),
    kw("секретный ключ", Strong, true),
    kw("секретного ключа", Strong, false),
    kw("закрытый ключ", Strong, false),
    kw("закрытого ключа", Strong, false),
    kw("сид-фраза", Strong, true),
    kw("сид фраза", Strong, false),
    kw("сид-фраз", Strong, false),
    kw("фраза восстановления", Strong, true),
    kw("фразы восстановления", Strong, false),
    kw("мнемоник", Strong, true),
    kw("электрум", Strong, false),
    kw("мультибит", Strong, false),
    kw("приватн", Weak, false),
    kw("ключ", Weak, false),
];

/// Encodings a keyword pattern was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Cp1251,
    Utf16Le,
}

impl TextEncoding {
    pub fn name(self) -> &'static str {
        match self {
            TextEncoding::Utf8 => "utf-8",
            TextEncoding::Cp1251 => "cp1251",
            TextEncoding::Utf16Le => "utf-16le",
        }
    }

    pub fn from_run(enc: Encoding) -> Self {
        match enc {
            Encoding::Ascii => TextEncoding::Utf8,
            _ => TextEncoding::Utf16Le,
        }
    }
}

/// Compiled keyword automaton (all case variants and encodings).
pub struct KeywordSet {
    ac: AhoCorasick,
    /// Pattern id -> (keyword index, encoding).
    meta: Vec<(usize, TextEncoding)>,
}

static SET: LazyLock<KeywordSet> = LazyLock::new(KeywordSet::build);

impl KeywordSet {
    pub fn get() -> &'static KeywordSet {
        &SET
    }

    fn build() -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut meta = Vec::new();
        for (ki, k) in KEYWORDS.iter().enumerate() {
            for variant in case_variants(k.text) {
                let mut push = |bytes: Vec<u8>, enc| {
                    if !patterns.contains(&bytes) {
                        patterns.push(bytes);
                        meta.push((ki, enc));
                    }
                };
                push(variant.as_bytes().to_vec(), TextEncoding::Utf8);
                if let Some(cp) = encode_cp1251(&variant) {
                    if !variant.is_ascii() {
                        push(cp, TextEncoding::Cp1251);
                    }
                }
                push(variant.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(), TextEncoding::Utf16Le);
            }
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("keyword automaton builds from static patterns");
        Self { ac, meta }
    }

    /// Every keyword occurrence in `data`: `(start, end, keyword, encoding)`.
    pub fn find_iter<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Iterator<Item = (usize, usize, &'static Keyword, TextEncoding)> + 'a {
        self.ac.find_iter(data).filter_map(move |m| {
            let (ki, enc) = *self.meta.get(m.pattern().as_usize())?;
            Some((m.start(), m.end(), KEYWORDS.get(ki)?, enc))
        })
    }
}

/// Lower, Capitalized and UPPER forms (ASCII case is handled by the automaton).
fn case_variants(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    if lower.is_ascii() {
        return vec![lower];
    }
    let mut cap = String::new();
    let mut chars = lower.chars();
    if let Some(first) = chars.next() {
        cap.extend(first.to_uppercase());
        cap.push_str(chars.as_str());
    }
    vec![lower.clone(), cap, lower.to_uppercase()]
}

/// Windows-1251 encoding for ASCII + Cyrillic; `None` for other characters.
pub fn encode_cp1251(text: &str) -> Option<Vec<u8>> {
    text.chars()
        .map(|c| match c as u32 {
            0..=0x7f => Some(c as u8),
            0x0410..=0x044f => Some((c as u32 - 0x0410 + 0xc0) as u8),
            0x0401 => Some(0xa8),
            0x0451 => Some(0xb8),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_all_encodings() {
        let set = KeywordSet::get();
        let mut data = b"xx BITCOIN yy ".to_vec();
        data.extend(encode_cp1251("Кошелёк").unwrap());
        data.extend("приватный ключ".as_bytes());
        data.extend("wallet.dat".encode_utf16().flat_map(|u| u.to_le_bytes()));
        let hits: Vec<_> = set.find_iter(&data).map(|(_, _, k, e)| (k.text, e)).collect();
        assert!(hits.contains(&("bitcoin", TextEncoding::Utf8)));
        assert!(hits.contains(&("кошелёк", TextEncoding::Cp1251)));
        assert!(hits.contains(&("приватный ключ", TextEncoding::Utf8)));
        assert!(hits.contains(&("wallet.dat", TextEncoding::Utf16Le)));
    }
}
