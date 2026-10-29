//! Word lookup across every BIP39 wordlist plus the Electrum 1.x ("old") list.
//!
//! Built once, lazily. Lookups take UTF-8 lowercase bytes and never allocate.

use bip39::Language;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

/// Number of BIP39 languages compiled in.
pub const BIP39_LANGS: usize = 10;
/// Bit used for the Electrum old wordlist in [`WordEntry::mask`].
pub const ELECTRUM_OLD_BIT: u16 = 1 << BIP39_LANGS;
const ABSENT: u16 = u16::MAX;

static ELECTRUM_OLD_TEXT: &str = include_str!("electrum_old_words.txt");

/// Positions of one spelling in each list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordEntry {
    bip39: [u16; BIP39_LANGS],
    electrum_old: u16,
    mask: u16,
}

impl WordEntry {
    const EMPTY: WordEntry = WordEntry { bip39: [ABSENT; BIP39_LANGS], electrum_old: ABSENT, mask: 0 };

    /// Bit `i` set when the word is in BIP39 language `i`; [`ELECTRUM_OLD_BIT`] for Electrum.
    pub fn mask(&self) -> u16 {
        self.mask
    }

    pub fn bip39_index(&self, lang: usize) -> Option<u16> {
        self.bip39.get(lang).copied().filter(|i| *i != ABSENT)
    }

    pub fn electrum_old_index(&self) -> Option<u16> {
        (self.electrum_old != ABSENT).then_some(self.electrum_old)
    }
}

/// Small multiplicative hasher: the keys are static wordlist spellings, not attacker-chosen
/// map keys, so SipHash's DoS resistance buys nothing on this hot path.
#[derive(Default)]
pub struct FxHasher(u64);

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(word)).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// All wordlists, indexed by spelling (NFC and NFKD forms both present).
pub struct WordIndex {
    map: HashMap<Box<[u8]>, WordEntry, BuildHasherDefault<FxHasher>>,
    /// Bitmap over the first two bytes of every spelling: cheap rejection before hashing.
    first2: Box<[u64; 1024]>,
    max_word_bytes: usize,
    electrum_old: Vec<&'static str>,
}

static INDEX: LazyLock<WordIndex> = LazyLock::new(WordIndex::build);

impl WordIndex {
    pub fn get() -> &'static WordIndex {
        &INDEX
    }

    fn build() -> Self {
        let mut index = WordIndex {
            map: HashMap::with_capacity_and_hasher(40_000, BuildHasherDefault::default()),
            first2: Box::new([0; 1024]),
            max_word_bytes: 0,
            electrum_old: ELECTRUM_OLD_TEXT.lines().filter(|l| !l.is_empty()).collect(),
        };
        for (li, lang) in Language::ALL.iter().enumerate().take(BIP39_LANGS) {
            for (wi, word) in lang.word_list().iter().enumerate() {
                index.add_spellings(word, |e| {
                    e.bip39[li] = wi as u16;
                    e.mask |= 1 << li;
                });
            }
        }
        let old = index.electrum_old.clone();
        for (wi, word) in old.iter().enumerate() {
            index.add_spellings(word, |e| {
                e.electrum_old = wi as u16;
                e.mask |= ELECTRUM_OLD_BIT;
            });
        }
        index
    }

    fn add_spellings(&mut self, word: &str, mut set: impl FnMut(&mut WordEntry)) {
        let nfc: String = word.nfc().collect();
        let nfkd: String = word.nfkd().collect();
        for spelling in [word.to_string(), nfc, nfkd] {
            let bytes = spelling.into_bytes();
            self.max_word_bytes = self.max_word_bytes.max(bytes.len());
            if let [a, b, ..] = bytes.as_slice() {
                let k = (usize::from(*a) << 8) | usize::from(*b);
                self.first2[k >> 6] |= 1 << (k & 63);
            }
            let entry = self.map.entry(bytes.into_boxed_slice()).or_insert(WordEntry::EMPTY);
            set(entry);
        }
    }

    /// Look up a lowercase UTF-8 spelling.
    #[inline]
    pub fn lookup(&self, word: &[u8]) -> Option<&WordEntry> {
        let [a, b, ..] = word else { return None };
        if word.len() > self.max_word_bytes {
            return None;
        }
        let k = (usize::from(*a) << 8) | usize::from(*b);
        if self.first2[k >> 6] & (1 << (k & 63)) == 0 {
            return None;
        }
        self.map.get(word)
    }

    pub fn max_word_bytes(&self) -> usize {
        self.max_word_bytes
    }

    pub fn electrum_old_words(&self) -> &[&'static str] {
        &self.electrum_old
    }

    pub fn bip39_language(lang: usize) -> Option<Language> {
        Language::ALL.get(lang).copied()
    }

    pub fn bip39_word(lang: usize, index: u16) -> Option<&'static str> {
        Self::bip39_language(lang)?.word_list().get(usize::from(index)).copied()
    }

    pub fn language_name(lang: usize) -> &'static str {
        match Self::bip39_language(lang) {
            Some(Language::English) => "english",
            Some(Language::SimplifiedChinese) => "chinese_simplified",
            Some(Language::TraditionalChinese) => "chinese_traditional",
            Some(Language::Czech) => "czech",
            Some(Language::French) => "french",
            Some(Language::Italian) => "italian",
            Some(Language::Japanese) => "japanese",
            Some(Language::Korean) => "korean",
            Some(Language::Portuguese) => "portuguese",
            Some(Language::Spanish) => "spanish",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_complete() {
        let idx = WordIndex::get();
        assert_eq!(idx.electrum_old_words().len(), 1626);
        let e = idx.lookup(b"abandon").unwrap();
        assert_eq!(e.bip39_index(0), Some(0));
        let e = idx.lookup(b"like").unwrap();
        assert_eq!(e.electrum_old_index(), Some(0));
        assert!(idx.lookup("ábaco".as_bytes()).is_some());
        assert!(idx.lookup(b"zzzzzz").is_none());
        assert!(idx.lookup(b"").is_none());
        assert_eq!(WordIndex::language_name(0), "english");
    }
}
