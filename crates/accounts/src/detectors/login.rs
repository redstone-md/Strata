use super::{confidence_for, service_details, url_char};
use crate::account::IdentifierKind;
use crate::catalogue::{Catalogue, ServiceKind};
use crate::service::Service;
use crate::text::char_at;
use crate::url_accounts::{LOGIN_FIELDS, UrlAccounts};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

/// Longest value read after `field=`.
const MAX_VALUE: usize = 96;
/// How far left to look for the URL the field belongs to.
const MAX_URL: usize = 512;
/// How far left to look for a service domain when the field is not inside a URL (form posts,
/// cookies, config files).
const NEAR_WINDOW: usize = 256;

struct Anchor {
    field: &'static str,
    kind: IdentifierKind,
    stride: usize,
}

/// `login=`, `user=`, `username=`, `email=`... in query strings and form-encoded data, ASCII
/// and UTF-16LE, reported only when the value sits inside a URL of a known service or a known
/// service domain appears right before it.
pub struct LoginDetector {
    ac: Option<AhoCorasick>,
    anchors: Vec<Anchor>,
}

impl Default for LoginDetector {
    fn default() -> Self {
        let mut patterns = Vec::new();
        let mut anchors = Vec::new();
        let fields = LOGIN_FIELDS.iter().copied().chain([("profile;u", IdentifierKind::UserId)]);
        for (field, kind) in fields {
            let ascii = format!("{field}=");
            let wide: Vec<u8> = ascii.bytes().flat_map(|b| [b, 0]).collect();
            patterns.push(ascii.into_bytes());
            anchors.push(Anchor { field, kind, stride: 1 });
            patterns.push(wide);
            anchors.push(Anchor { field, kind, stride: 2 });
        }
        let ac = AhoCorasickBuilder::new().ascii_case_insensitive(true).match_kind(MatchKind::LeftmostLongest).build(&patterns).ok();
        Self { ac, anchors }
    }
}

fn value_char(c: u8) -> bool {
    c.is_ascii_graphic() && !b"&;#\"'<>,()[]{}\\|`".contains(&c)
}

/// `count` characters left of `pos` (exclusive) narrowed to ASCII; unprintable bytes become
/// spaces so domains on either side never glue together.
fn left_text(chunk: &[u8], pos: usize, stride: usize, count: usize, keep: impl Fn(u8) -> bool) -> String {
    let mut chars: Vec<char> = Vec::new();
    for i in 1..=count as isize {
        match char_at(chunk, pos, stride, -i) {
            Some(c) if keep(c) => chars.push(c as char),
            _ => break,
        }
    }
    chars.iter().rev().collect()
}

impl LoginDetector {
    /// The service a value at `pos` belongs to and whether it was found inside its URL.
    fn context(chunk: &[u8], pos: usize, stride: usize) -> Option<(Service, bool)> {
        let token = left_text(chunk, pos, stride, MAX_URL, url_char);
        let url_start = token.find("://").and_then(|i| token[..i].rfind(|c: char| !c.is_ascii_alphabetic()).map_or(Some(0), |j| Some(j + 1)));
        let url_start = url_start.or_else(|| token.to_ascii_lowercase().find("www."));
        if let Some(start) = url_start {
            return Service::classify_url(&token[start..]).map(|s| (s, true));
        }
        let window = left_text(chunk, pos, stride, NEAR_WINDOW, |c| c != 0).replace(|c: char| !c.is_ascii_graphic(), " ");
        let entry = Catalogue::shared().last_domain_in(&window)?;
        Service::by_id(entry.id()).map(|s| (s, false))
    }
}

impl Detector for LoginDetector {
    fn id(&self) -> &'static str {
        "accounts.login"
    }

    fn max_match(&self) -> usize {
        2 * (MAX_URL + 16 + MAX_VALUE)
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let Some(ac) = &self.ac else { return };
        for m in ac.find_iter(chunk) {
            let Some(anchor) = self.anchors.get(m.pattern().as_usize()) else { continue };
            let stride = anchor.stride;
            // The field name must start a key: `xlogin=` or `my_user=` is something else.
            if char_at(chunk, m.start(), stride, -1).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                continue;
            }
            let raw: String = (0..MAX_VALUE as isize).map_while(|i| char_at(chunk, m.end(), stride, i).filter(|c| value_char(*c))).map(char::from).collect();
            let Some(value) = UrlAccounts::clean_value(&raw, anchor.kind) else { continue };
            let Some((service, in_url)) = Self::context(chunk, m.start(), stride).filter(|(s, _)| s.kind != ServiceKind::Other) else {
                continue;
            };
            let kind = if value.contains('@') { IdentifierKind::Email } else { anchor.kind };
            let mut details = service_details(Some(service), stride == 2);
            details["field"] = serde_json::json!(anchor.field);
            details["context"] = serde_json::json!(if in_url { "url" } else { "nearby" });
            let confidence = confidence_for(Some(service));
            sink.emit(
                Hit::new(self.id(), HitCategory::Identity, base + m.start() as u64, m.len() + raw.len() * stride)
                    .label(format!("{} ({})", kind.label(), if in_url { "url" } else { "form" }))
                    .value(if kind == IdentifierKind::Email { value.to_ascii_lowercase() } else { value })
                    .confidence(if in_url { confidence } else { confidence.scaled(0.8) })
                    .details(details),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(data: &[u8]) -> Vec<Hit> {
        let mut hits = Vec::new();
        LoginDetector::default().scan(data, 0, &mut hits);
        hits
    }

    fn wide(s: &str) -> Vec<u8> {
        s.bytes().flat_map(|b| [b, 0]).collect()
    }

    #[test]
    fn values_inside_service_urls() {
        let hits = scan(b"GET https://mtgox.com/code/login.php?username=Satoshi_Fan&password=x HTTP/1.1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "Satoshi_Fan");
        assert_eq!(hits[0].label, "login (url)");
        assert_eq!(hits[0].details["service_id"], "mtgox");
        let hits = scan(&wide("x https://bitcointalk.org/index.php?action=profile;u=424242 y"));
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].value.as_str(), hits[0].label.as_str()), ("424242", "user id (url)"));
        let hits = scan(b"http://www.btc-e.com/profile?EMAIL=Ivan.Test2%40mail.ru&x=1");
        assert_eq!(hits[0].value, "ivan.test2@mail.ru");
    }

    #[test]
    fn form_values_near_a_service_domain() {
        let post = b"POST /login HTTP/1.1\r\nHost: www.bitstamp.net\r\nContent-Type: x\r\n\r\nuser=trader_test&pass=x";
        let hits = scan(post);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "login (form)");
        assert_eq!(hits[0].details["context"], "nearby");
    }

    #[test]
    fn ignores_unknown_sites_placeholders_and_glued_keys() {
        assert!(scan(b"https://example.com/?login=someone").is_empty());
        assert!(scan(b"https://mtgox.com/?login=null&user=%s&nouser=abc").is_empty());
        assert!(scan(b"random binary user=abc without any domain").is_empty());
        assert!(scan(b"https://vk.com/?xlogin=abcdef").is_empty());
    }
}
