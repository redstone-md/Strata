//! Event tagging: known services (via `strata_accounts::Service`) and crypto keywords.

use std::sync::OnceLock;
use strata_accounts::{Service, ServiceKind};
use strata_timeline::{CRYPTO_TAG, TimelineEvent};

/// Crypto keywords (lowercase). `btc` and `coin` are matched as whole words only, the rest as
/// substrings. Data table: the single place to extend.
const CRYPTO_WORDS: &[&str] = &[
    "bitcoin",
    "wallet.dat",
    "electrum",
    "multibit",
    "armory",
    "satoshi",
    "blockchain",
    "litecoin",
    "privkey",
    "биткоин",
    "биткойн",
    "кошелёк",
    "кошелек",
    "кошельк",
    "криптовалют",
];

/// Whole-word crypto tokens.
const CRYPTO_TOKENS: &[&str] = &["btc", "wallet", "mining", "miner"];

pub(crate) struct Tagger;

impl Tagger {
    pub fn shared() -> &'static Tagger {
        static TAGGER: OnceLock<Tagger> = OnceLock::new();
        TAGGER.get_or_init(|| Tagger)
    }

    /// Tags for free text: service kind + name, and `crypto` + `kw:<word>` for keywords.
    pub fn tags_for(&self, text: &str) -> Vec<String> {
        let mut tags = Vec::new();
        if let Some(service) = Service::classify(text) {
            if let Some(kind) = kind_tag(service.kind) {
                tags.push(kind.to_string());
            }
            tags.push(service.name.to_string());
        }
        let lower = text.to_lowercase();
        let mut keyword = |w: &str| {
            tags.push(CRYPTO_TAG.to_string());
            tags.push(format!("kw:{w}"));
        };
        for w in CRYPTO_WORDS.iter().filter(|w| lower.contains(*w)) {
            keyword(w);
        }
        for w in CRYPTO_TOKENS.iter().filter(|w| has_word(&lower, w)) {
            keyword(w);
        }
        tags
    }

    pub fn tag_event(&self, event: &mut TimelineEvent) {
        let text = format!("{} {}", event.title(), event.detail());
        for t in self.tags_for(&text) {
            event.add_tag(t);
        }
    }

    pub fn service_name(&self, text: &str) -> Option<String> {
        Service::classify(text).map(|s| s.name.to_string())
    }
}

fn kind_tag(kind: ServiceKind) -> Option<&'static str> {
    match kind {
        ServiceKind::Crypto => Some(CRYPTO_TAG),
        ServiceKind::Payment => Some("payment"),
        ServiceKind::Mail => Some("mail"),
        ServiceKind::Social => Some("social"),
        ServiceKind::Other => None,
    }
}

/// `word` appears delimited by non-alphanumerics (ASCII sense).
fn has_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(pos) = haystack.get(from..).and_then(|h| h.find(word)) {
        let start = from + pos;
        let end = start + word.len();
        let before = start == 0 || !bytes.get(start - 1).is_some_and(u8::is_ascii_alphanumeric);
        let after = !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
        if before && after {
            return true;
        }
        from = end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_services_and_keywords() {
        let t = Tagger::shared();
        let tags = t.tags_for("https://bitcointalk.org/index.php?topic=1");
        assert!(tags.contains(&"crypto".to_string()));
        assert!(tags.contains(&"Bitcointalk".to_string()));
        assert!(t.tags_for("https://wmtransfer.com/").contains(&"payment".to_string()));
        assert!(t.tags_for("Мой биткоин кошелёк").contains(&"kw:биткоин".to_string()));
        assert!(t.tags_for("send 1 BTC now").contains(&"kw:btc".to_string()));
        assert!(t.tags_for("abtcd").is_empty());
        assert!(t.tags_for("http://example.com").is_empty());
    }
}
