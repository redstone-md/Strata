//! Word-run tokenizer for seed phrases in UTF-8 (incl. ASCII) and UTF-16LE text.
//!
//! Collects consecutive wordlist words separated only by "soft" separators (whitespace,
//! punctuation, list numbering) and hands each run to a callback once it ends.

use crate::keys::mnemonic::{WordEntry, WordIndex};

/// A wordlist word found in the chunk.
#[derive(Debug, Clone, Copy)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub entry: &'static WordEntry,
    /// A line break or phrase punctuation sits between this word and the previous one.
    pub break_before: bool,
}

/// Longest gap (bytes) of soft separators allowed between two words of a run.
const MAX_GAP: usize = 24;
/// Longest word buffer (bytes, UTF-8).
const WORD_BUF: usize = 48;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Part of a word.
    Letter,
    /// A word on its own (CJK ideograph).
    Ideograph,
    /// Whitespace, punctuation, digits: may sit between words of a run.
    Soft,
    /// Anything else ends the run.
    Hard,
}

fn classify(c: char) -> Class {
    if c.is_ascii() {
        return match c {
            'a'..='z' | 'A'..='Z' => Class::Letter,
            ' ' | '\t' | '\r' | '\n' | ',' | '.' | ';' | ':' | '-' | ')' | '(' | '"' | '\''
            | '#' | '/' | '|' | '[' | ']' | '0'..='9' => Class::Soft,
            _ => Class::Hard,
        };
    }
    match c as u32 {
        0x4E00..=0x9FFF | 0x3400..=0x4DBF => Class::Ideograph,
        0x3000 | 0x00A0 | 0x3001 | 0x3002 => Class::Soft,
        _ if c.is_alphabetic() || unicode_normalization::char::is_combining_mark(c) => Class::Letter,
        _ if c.is_whitespace() => Class::Soft,
        _ => Class::Hard,
    }
}

/// Streaming tokenizer state.
pub struct Tokenizer<'f> {
    index: &'static WordIndex,
    word: [u8; WORD_BUF],
    word_len: usize,
    word_overflow: bool,
    word_start: usize,
    saw_break: bool,
    last_end: usize,
    run: Vec<Token>,
    run_mask: u16,
    on_run: &'f mut dyn FnMut(&[Token]),
}

impl<'f> Tokenizer<'f> {
    pub fn new(on_run: &'f mut dyn FnMut(&[Token])) -> Self {
        Self {
            index: WordIndex::get(),
            word: [0; WORD_BUF],
            word_len: 0,
            word_overflow: false,
            word_start: 0,
            saw_break: false,
            last_end: 0,
            run: Vec::with_capacity(64),
            run_mask: 0,
            on_run,
        }
    }

    /// Feed one character occupying `chunk[pos..end]`.
    #[inline]
    pub fn feed(&mut self, pos: usize, end: usize, c: char) {
        match classify(c) {
            Class::Letter => {
                if self.word_len == 0 && !self.word_overflow {
                    self.word_start = pos;
                }
                self.push_char(c);
            }
            Class::Ideograph => {
                self.finish_word(pos);
                self.word_start = pos;
                self.push_char(c);
                self.finish_word(end);
            }
            Class::Soft => {
                self.finish_word(pos);
                if matches!(c, '\n' | '\r' | '\t' | ':' | '.' | ';' | ',' | '|' | ')' | '"' | '\'' | '0'..='9') {
                    self.saw_break = true;
                }
                if !self.run.is_empty() && pos.saturating_sub(self.last_end) > MAX_GAP {
                    self.close_run();
                }
            }
            Class::Hard => {
                self.finish_word(pos);
                self.close_run();
            }
        }
    }

    /// Fast path for bytes that cannot start or continue a word (invalid UTF-8, NUL...).
    #[inline]
    pub fn hard(&mut self, pos: usize) {
        if self.word_len != 0 || self.word_overflow {
            self.finish_word(pos);
        }
        if !self.run.is_empty() {
            self.close_run();
        }
    }

    /// Fast path: a run of ASCII letters (part of the current word).
    #[inline]
    pub fn ascii_letters(&mut self, pos: usize, letters: &[u8]) {
        if self.word_len == 0 && !self.word_overflow {
            self.word_start = pos;
        }
        if self.word_overflow {
            return;
        }
        match self.word.get_mut(self.word_len..self.word_len + letters.len()) {
            Some(slot) => {
                for (d, s) in slot.iter_mut().zip(letters) {
                    *d = s.to_ascii_lowercase();
                }
                self.word_len += letters.len();
            }
            None => self.word_overflow = true,
        }
    }

    fn push_char(&mut self, c: char) {
        if self.word_overflow {
            return;
        }
        let lower = if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c };
        let mut tmp = [0u8; 4];
        let bytes = lower.encode_utf8(&mut tmp).as_bytes();
        match self.word.get_mut(self.word_len..self.word_len + bytes.len()) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                self.word_len += bytes.len();
            }
            None => self.word_overflow = true,
        }
    }

    fn finish_word(&mut self, end: usize) {
        if self.word_len == 0 && !self.word_overflow {
            return;
        }
        let entry = if self.word_overflow { None } else { self.index.lookup(&self.word[..self.word_len]) };
        self.word_len = 0;
        self.word_overflow = false;
        match entry {
            Some(entry) => {
                let break_before = std::mem::take(&mut self.saw_break);
                self.push_token(Token { start: self.word_start, end, entry, break_before });
            }
            None => self.close_run(),
        }
    }

    fn push_token(&mut self, token: Token) {
        let mask = token.entry.mask();
        // Unseparated ideographs are prose, not a written-down phrase.
        if !self.run.is_empty() && token.start == self.last_end {
            self.close_run();
        }
        if self.run.is_empty() || self.run_mask & mask != 0 {
            self.run_mask = if self.run.is_empty() { mask } else { self.run_mask & mask };
            self.run.push(token);
            self.last_end = token.end;
            return;
        }
        // List conflict: close the run, keep the longest suffix compatible with this word.
        let mut keep_from = self.run.len();
        let mut suffix_mask = mask;
        while keep_from > 0 && self.run[keep_from - 1].entry.mask() & suffix_mask != 0 {
            suffix_mask &= self.run[keep_from - 1].entry.mask();
            keep_from -= 1;
        }
        let carried: Vec<Token> = self.run[keep_from..].to_vec();
        self.close_run();
        self.run.extend(carried);
        self.run_mask = suffix_mask;
        self.run.push(token);
        self.last_end = token.end;
    }

    /// End the current run and report it when long enough to hold a phrase.
    pub fn close_run(&mut self) {
        if self.run.len() >= 12 {
            (self.on_run)(&self.run);
        }
        self.run.clear();
        self.run_mask = 0;
    }

    /// Flush at end of input.
    pub fn finish(&mut self, end: usize) {
        self.finish_word(end);
        self.close_run();
    }
}

/// Drive the tokenizer over UTF-8 / ASCII bytes.
pub fn tokenize_utf8(chunk: &[u8], tok: &mut Tokenizer<'_>) {
    let mut i = 0;
    while i < chunk.len() {
        let b = chunk[i];
        if b.is_ascii_alphabetic() {
            let mut j = i + 1;
            while j < chunk.len() && chunk[j].is_ascii_alphabetic() {
                j += 1;
            }
            tok.ascii_letters(i, &chunk[i..j]);
            i = j;
            continue;
        }
        if b < 0x80 {
            tok.feed(i, i + 1, b as char);
            i += 1;
            continue;
        }
        let width = match b {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 0,
        };
        let decoded = (width > 0)
            .then(|| chunk.get(i..i + width))
            .flatten()
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| s.chars().next());
        match decoded {
            Some(c) => {
                tok.feed(i, i + width, c);
                i += width;
            }
            None => {
                tok.hard(i);
                i += 1;
            }
        }
    }
    tok.finish(chunk.len());
}

/// Drive the tokenizer over UTF-16LE units starting at `align` (0 or 1).
pub fn tokenize_utf16le(chunk: &[u8], align: usize, tok: &mut Tokenizer<'_>) {
    let mut i = align;
    while i + 1 < chunk.len() {
        let unit = u16::from_le_bytes([chunk[i], chunk[i + 1]]);
        match char::from_u32(u32::from(unit)) {
            // Surrogates and NUL end runs; UTF-16 text with seeds is BMP-only in practice.
            Some(c) if unit != 0 => tok.feed(i, i + 2, c),
            _ => tok.hard(i),
        }
        i += 2;
    }
    tok.finish(chunk.len());
}
