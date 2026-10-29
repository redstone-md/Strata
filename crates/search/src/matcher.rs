//! A compiled query, run by the scan engine like any other detector.
//!
//! Text and hex compile to byte patterns for one Aho-Corasick automaton (ASCII letters fold
//! case inside it; non-ASCII letters get their lower, upper and title-case spellings as extra
//! patterns). Regex runs `regex::bytes` over the raw bytes and, when a UTF-16 encoding is
//! selected, over decoded UTF-16 text runs, which is several times slower.

use crate::query::{Pattern, SearchQuery};
use crate::utf16::Utf16Runs;
use crate::Encoding;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

/// Bytes of context kept on each side of a match.
pub const CONTEXT: usize = 64;
/// Longest regex match reported; longer ones are cut (and may be missed across chunks).
pub const MAX_REGEX_MATCH: usize = 1024;

pub const DETECTOR_ID: &str = "search.query";

enum Engine {
    Literal { automaton: AhoCorasick, encodings: Vec<Encoding>, longest: usize },
    Regex { bytes: regex::bytes::Regex, text: Option<(regex::Regex, Vec<Encoding>)> },
}

pub struct SearchMatcher {
    engine: Engine,
}

impl SearchMatcher {
    pub fn compile(query: &SearchQuery) -> Result<Self, String> {
        let engine = match &query.pattern {
            Pattern::Text(text) if text.is_empty() => return Err("Type something to search for.".into()),
            Pattern::Text(text) => Self::literal(Self::encoded(text, &query.encodings, query.case_insensitive)?, query.case_insensitive)?,
            Pattern::Hex(bytes) if bytes.is_empty() => return Err("Hex pattern is empty.".into()),
            Pattern::Hex(bytes) => Self::literal(vec![(bytes.clone(), Encoding::Ascii)], false)?,
            Pattern::Regex(re) => Self::regex(re, &query.encodings, query.case_insensitive)?,
        };
        Ok(Self { engine })
    }

    /// Every spelling of `text` in every selected encoding, deduplicated (the first encoding
    /// in [`Encoding::ALL`] order names a pattern shared by several).
    fn encoded(text: &str, encodings: &[Encoding], fold: bool) -> Result<Vec<(Vec<u8>, Encoding)>, String> {
        let mut spellings = vec![text.to_string()];
        if fold && !text.is_ascii() {
            spellings.extend([text.to_lowercase(), text.to_uppercase(), title_case(text)]);
        }
        let mut selected = encodings.to_vec();
        selected.sort();
        selected.dedup();
        let mut out: Vec<(Vec<u8>, Encoding)> = Vec::new();
        for e in selected {
            for s in &spellings {
                if let Some(bytes) = e.encode(s).filter(|b| !out.iter().any(|(o, _)| o == b)) {
                    out.push((bytes, e));
                }
            }
        }
        if out.is_empty() {
            return Err("None of the selected encodings can represent this text.".into());
        }
        Ok(out)
    }

    fn literal(patterns: Vec<(Vec<u8>, Encoding)>, fold: bool) -> Result<Engine, String> {
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(fold)
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns.iter().map(|(p, _)| p))
            .map_err(|e| e.to_string())?;
        let longest = patterns.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
        Ok(Engine::Literal { automaton, encodings: patterns.into_iter().map(|(_, e)| e).collect(), longest })
    }

    fn regex(re: &str, encodings: &[Encoding], fold: bool) -> Result<Engine, String> {
        let bytes = regex::bytes::RegexBuilder::new(re).case_insensitive(fold).build().map_err(|e| e.to_string())?;
        let wide: Vec<Encoding> = encodings.iter().copied().filter(|e| e.unit() == 2).collect();
        let text = if wide.is_empty() {
            None
        } else {
            Some((regex::RegexBuilder::new(re).case_insensitive(fold).build().map_err(|e| e.to_string())?, wide))
        };
        Ok(Engine::Regex { bytes, text })
    }

    /// Longest match plus trailing context, so chunk overlap carries the whole snippet.
    fn reach(&self) -> usize {
        match &self.engine {
            Engine::Literal { longest, .. } => longest + CONTEXT,
            Engine::Regex { .. } => MAX_REGEX_MATCH + CONTEXT,
        }
    }

    /// `(start, len, encoding)` of every match in `data`.
    pub fn find(&self, data: &[u8]) -> Vec<(usize, usize, Encoding)> {
        match &self.engine {
            Engine::Literal { automaton, encodings, .. } => automaton
                .find_iter(data)
                .filter_map(|m| {
                    let e = *encodings.get(m.pattern().as_usize())?;
                    Some((m.start(), m.len(), e))
                })
                .collect(),
            Engine::Regex { bytes, text } => {
                let mut out: Vec<(usize, usize, Encoding)> = bytes
                    .find_iter(data)
                    .filter(|m| !m.is_empty())
                    .map(|m| (m.start(), m.len().min(MAX_REGEX_MATCH), Encoding::Utf8))
                    .collect();
                if let Some((re, wide)) = text {
                    for e in wide {
                        for run in Utf16Runs::new(data, *e) {
                            out.extend(re.find_iter(run.text()).filter(|m| !m.is_empty()).map(|m| {
                                let (start, end) = run.byte_span(m.start(), m.end());
                                (start, (end - start).min(MAX_REGEX_MATCH), *e)
                            }));
                        }
                    }
                }
                out
            }
        }
    }
}

fn title_case(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start = true;
    for c in text.chars() {
        if start {
            out.extend(c.to_uppercase());
        } else {
            out.extend(c.to_lowercase());
        }
        start = !c.is_alphanumeric();
    }
    out
}

/// The matcher as a scan-engine detector: one hit per match, encoding in the label.
pub struct SearchDetector {
    matcher: SearchMatcher,
}

impl SearchDetector {
    pub fn new(matcher: SearchMatcher) -> Self {
        Self { matcher }
    }

    pub fn encoding_of(hit: &Hit) -> Encoding {
        hit.details.get("encoding").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or(Encoding::Utf8)
    }
}

impl Detector for SearchDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn max_match(&self) -> usize {
        self.matcher.reach()
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        for (start, len, encoding) in self.matcher.find(chunk) {
            sink.emit(
                Hit::new(DETECTOR_ID, HitCategory::Marker, base + start as u64, len)
                    .label(encoding.name())
                    .details(serde_json::json!({ "encoding": encoding })),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Scope;

    fn query(pattern: Pattern, encodings: &[Encoding], ci: bool) -> SearchMatcher {
        SearchMatcher::compile(&SearchQuery { pattern, encodings: encodings.to_vec(), case_insensitive: ci, scope: Scope::WholeDisk }).unwrap()
    }

    #[test]
    fn text_in_several_encodings_and_cases() {
        let m = query(Pattern::Text("Кошелёк wallet".into()), &[Encoding::Utf16Le, Encoding::Cp1251, Encoding::Utf8], true);
        let mut data = vec![0u8; 64];
        data.extend(Encoding::Utf16Le.encode("КОШЕЛЁК WALLET").unwrap());
        data.extend(b"....");
        data.extend(Encoding::Cp1251.encode("кошелёк Wallet").unwrap());
        data.extend(b"....");
        data.extend("Кошелёк WaLLet".as_bytes());
        let found = m.find(&data);
        let encodings: Vec<Encoding> = found.iter().map(|f| f.2).collect();
        assert_eq!(encodings, vec![Encoding::Utf16Le, Encoding::Cp1251, Encoding::Utf8], "{found:?}");
        assert_eq!(found[0].0, 64);
    }

    #[test]
    fn case_sensitive_and_hex() {
        let m = query(Pattern::Text("Seed".into()), &[Encoding::Ascii], false);
        assert_eq!(m.find(b"seed Seed SEED").len(), 1);
        let m = query(Pattern::hex("de ad be ef").unwrap(), &[], false);
        assert_eq!(m.find(b"\x00\xDE\xAD\xBE\xEF")[0].0, 1);
    }

    #[test]
    fn regex_over_bytes_and_utf16() {
        let m = query(Pattern::Regex(r"pass\w*=\d+".into()), &[Encoding::Utf8, Encoding::Utf16Le], true);
        let mut data = b"xx PASSWORD=1234 yy ".to_vec();
        data.extend(Encoding::Utf16Le.encode("pass=99").unwrap());
        let found = m.find(&data);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!((found[0].0, found[0].1, found[0].2), (3, 13, Encoding::Utf8));
        assert_eq!((found[1].0, found[1].1, found[1].2), (20, 14, Encoding::Utf16Le));
    }

    #[test]
    fn rejects_unrepresentable_text() {
        let q = SearchQuery { pattern: Pattern::Text("日本".into()), encodings: vec![Encoding::Cp1251], case_insensitive: true, scope: Scope::WholeDisk };
        assert!(SearchMatcher::compile(&q).is_err());
    }
}
