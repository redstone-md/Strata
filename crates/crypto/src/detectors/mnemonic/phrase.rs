//! Turning a word run into validated phrases: BIP39 windows (all languages),
//! Electrum 2.x and Electrum 1.x whole-run checks.

use super::tokenizer::Token;
use crate::keys::mnemonic::{
    checksum_ok, old_indices_to_hex, Bip39Mnemonic, ElectrumSeed, BIP39_LANGS, ELECTRUM_OLD_BIT,
};

/// Runs longer than this are word lists or prose, not written-down seeds.
const MAX_RUN_WORDS: usize = 96;
const SIZES: [usize; 5] = [24, 21, 18, 15, 12];
/// Longest run searched for Electrum phrases (phrase plus a few label words).
const MAX_ELECTRUM_RUN: usize = 15;

#[derive(Debug, Clone)]
pub enum PhraseKind {
    Bip39(Bip39Mnemonic),
    Electrum(ElectrumSeed),
}

/// A validated phrase located in the chunk.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub words: usize,
    /// The whole run is exactly this phrase (no extra words around it).
    pub exact: bool,
    /// Words minus distinct words.
    pub repeats: usize,
    pub kind: PhraseKind,
}

impl Candidate {
    /// Move offsets from region-relative to chunk-relative.
    pub fn shifted(mut self, by: usize) -> Self {
        self.start += by;
        self.end += by;
        self
    }
}

/// Validate every phrase inside `run`.
pub fn evaluate(run: &[Token], out: &mut Vec<Candidate>) {
    let len = run.len();
    if !(12..=MAX_RUN_WORDS).contains(&len) {
        return;
    }
    let mask = run.iter().fold(u16::MAX, |m, t| m & t.entry.mask());
    let mut covered = vec![false; len];
    let mut found_bip39 = false;
    for lang in (0..BIP39_LANGS).filter(|l| mask & (1 << l) != 0) {
        let mut idx = [0u16; 24];
        for size in SIZES.into_iter().filter(|s| *s <= len) {
            for at in 0..=len - size {
                if !bounded(run, at, size) || covered[at..at + size].iter().any(|c| *c) {
                    continue;
                }
                for (slot, t) in idx.iter_mut().zip(&run[at..at + size]) {
                    *slot = t.entry.bip39_index(lang).unwrap_or(u16::MAX);
                }
                if !checksum_ok(&idx[..size]) {
                    continue;
                }
                let Some(m) = Bip39Mnemonic::from_indices(lang, &idx[..size]) else { continue };
                covered[at..at + size].iter_mut().for_each(|c| *c = true);
                found_bip39 = true;
                out.push(candidate(run, at, size, PhraseKind::Bip39(m)));
            }
        }
    }
    if found_bip39 {
        return;
    }
    if len > MAX_ELECTRUM_RUN && len != 24 {
        return;
    }
    // Electrum seeds are written as 12/13 (2.x) or 12/24 (1.x) words; allow a label word
    // or two around them ("seed: ...").
    for size in [24, 13, 12].into_iter().filter(|s| *s <= len) {
        for at in 0..=len - size {
            if !bounded(run, at, size) {
                continue;
            }
            let window = &run[at..at + size];
            let wmask = window.iter().fold(u16::MAX, |m, t| m & t.entry.mask());
            let old = wmask & ELECTRUM_OLD_BIT != 0 && size != 13 && {
                let idx: Option<Vec<u16>> = window.iter().map(|t| t.entry.electrum_old_index()).collect();
                idx.as_deref().and_then(old_indices_to_hex).is_some()
            };
            let new = wmask & 1 != 0 && size != 24;
            if !(old || new) {
                continue;
            }
            if let Some(seed) = ElectrumSeed::detect(&phrase_text(window)) {
                out.push(candidate(run, at, size, PhraseKind::Electrum(seed)));
                return;
            }
        }
    }
}

/// A window must start and end at a natural boundary (run edge, line break, punctuation):
/// seeds are written as their own line or list, not in the middle of a sentence.
fn bounded(run: &[Token], at: usize, size: usize) -> bool {
    let starts = at == 0 || run[at].break_before;
    let ends = run.get(at + size).is_none_or(|next| next.break_before);
    starts && ends
}

fn candidate(run: &[Token], at: usize, size: usize, kind: PhraseKind) -> Candidate {
    let window = &run[at..at + size];
    let distinct = window
        .iter()
        .enumerate()
        .filter(|(i, t)| !window[..*i].iter().any(|p| std::ptr::eq(p.entry, t.entry)))
        .count();
    Candidate {
        repeats: size - distinct,
        start: run[at].start,
        end: run[at + size - 1].end,
        words: size,
        exact: size == run.len(),
        kind,
    }
}

/// English spelling of the run (Electrum checks operate on English words).
fn phrase_text(run: &[Token]) -> String {
    let words: Vec<&str> = run
        .iter()
        .filter_map(|t| {
            t.entry
                .bip39_index(0)
                .and_then(|i| crate::keys::mnemonic::WordIndex::bip39_word(0, i))
                .or_else(|| {
                    let i = t.entry.electrum_old_index()?;
                    crate::keys::mnemonic::WordIndex::get().electrum_old_words().get(usize::from(i)).copied()
                })
        })
        .collect();
    words.join(" ")
}
