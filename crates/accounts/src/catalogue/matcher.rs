//! One Aho-Corasick pass over every domain and keyword of the catalogue, then a word-boundary
//! check per match. Replaces a per-entry substring search: the cost no longer grows with the
//! number of services.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// How a needle was declared; also its rank when several needles match (higher wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NeedleKind {
    Keyword,
    Domain,
    /// A domain with a path (`reddit.com/r/bitcoin`): more specific than its host.
    Path,
}

#[derive(Debug, Clone, Copy)]
struct Needle {
    entry: usize,
    kind: NeedleKind,
    /// Boundary checks apply only on sides that end in a letter or digit (`.wallet` may follow
    /// a file name directly).
    word_start: bool,
    word_end: bool,
}

/// A boundary-checked match: byte range in the haystack and the entry it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Found {
    pub entry: usize,
    pub kind: NeedleKind,
    pub start: usize,
    pub end: usize,
}

impl Found {
    fn rank(&self) -> (NeedleKind, usize) {
        (self.kind, self.end - self.start)
    }
}

pub(crate) struct Matcher {
    ac: Option<AhoCorasick>,
    needles: Vec<Needle>,
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

impl Matcher {
    /// `patterns`: `(lowercase text, entry index, kind)`.
    pub fn new(patterns: Vec<(String, usize, NeedleKind)>) -> Self {
        let needles = patterns
            .iter()
            .map(|(text, entry, kind)| Needle {
                entry: *entry,
                kind: *kind,
                word_start: text.bytes().next().is_some_and(is_word),
                word_end: text.bytes().last().is_some_and(is_word),
            })
            .collect();
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|(t, _, _)| t.as_str()))
            .ok();
        Self { ac, needles }
    }

    /// Every needle occurrence in `hay` that sits on word boundaries (overlaps included).
    pub fn find_all<'a>(&'a self, hay: &'a [u8]) -> impl Iterator<Item = Found> + 'a {
        self.ac.iter().flat_map(move |ac| ac.find_overlapping_iter(hay)).filter_map(move |m| {
            let needle = self.needles.get(m.pattern().as_usize())?;
            let before_ok = !needle.word_start || m.start() == 0 || !hay.get(m.start() - 1).copied().is_some_and(is_word);
            let after_ok = !needle.word_end || !hay.get(m.end()).copied().is_some_and(is_word);
            (before_ok && after_ok).then_some(Found { entry: needle.entry, kind: needle.kind, start: m.start(), end: m.end() })
        })
    }

    /// The most specific accepted match: paths over domains over keywords, then the longest.
    pub fn best(&self, hay: &[u8], accept: impl Fn(&Found) -> bool) -> Option<Found> {
        self.find_all(hay).filter(|f| accept(f)).max_by(|a, b| a.rank().cmp(&b.rank()).then(b.start.cmp(&a.start)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> Matcher {
        Matcher::new(vec![
            ("vk.com".into(), 0, NeedleKind::Domain),
            ("skype".into(), 1, NeedleKind::Keyword),
            (".wallet".into(), 2, NeedleKind::Keyword),
            ("reddit.com".into(), 3, NeedleKind::Domain),
            ("reddit.com/r/bitcoin".into(), 4, NeedleKind::Path),
        ])
    }

    #[test]
    fn word_boundaries() {
        let m = matcher();
        let entries = |s: &str| m.find_all(s.as_bytes()).map(|f| f.entry).collect::<Vec<_>>();
        assert_eq!(entries("http://VK.com/id1"), [0]);
        assert!(entries("qvk.community").is_empty());
        assert_eq!(entries("specslujbi_proslushivat_skype.html"), [1]);
        assert!(entries("skyper").is_empty());
        assert_eq!(entries("backup.wallet"), [2]);
        assert!(entries("x.walletx").is_empty());
    }

    #[test]
    fn most_specific_wins() {
        let m = matcher();
        let best = |s: &str| m.best(s.as_bytes(), |_| true).map(|f| f.entry);
        assert_eq!(best("https://www.reddit.com/r/bitcoin/comments/x"), Some(4));
        assert_eq!(best("https://www.reddit.com/r/bitcoinmining"), Some(3));
        assert_eq!(best("nothing here"), None);
    }
}
