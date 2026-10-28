use crate::service::{Service, ServiceKind};
use crate::text::wide_runs;
use regex::bytes::Regex;
use std::sync::Arc;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

/// Shared driver: run `regex` over ASCII bytes and UTF-16LE runs, report absolute offsets.
struct TextMatcher {
    regex: Regex,
}

impl TextMatcher {
    fn new(pattern: &str) -> Self {
        Self { regex: Regex::new(pattern).expect("static pattern") }
    }

    /// Calls `f(raw_offset, raw_len, matched_text, is_wide)`.
    fn each(&self, chunk: &[u8], mut f: impl FnMut(usize, usize, &str, bool)) {
        for m in self.regex.find_iter(chunk) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                f(m.start(), m.len(), s, false);
            }
        }
        // Cheap prefilter: UTF-16 text has many `x 00` pairs; skip chunks without any.
        if !chunk.windows(4).any(|w| w[1] == 0 && w[3] == 0 && w[0] > 0x20 && w[2] > 0x20) {
            return;
        }
        for run in wide_runs(chunk, 6) {
            for m in self.regex.find_iter(&run.text) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    f(run.start + 2 * m.start(), 2 * m.len(), s, true);
                }
            }
        }
    }
}

fn service_details(text: &str, wide: bool) -> (serde_json::Value, Option<Service>) {
    let service = Service::classify(text);
    let details = serde_json::json!({
        "encoding": if wide { "utf-16le" } else { "ascii" },
        "service": service.map(|s| s.name),
        "service_kind": service.map(|s| format!("{:?}", s.kind)),
    });
    (details, service)
}

fn confidence_for(service: Option<Service>) -> Confidence {
    match service.map(|s| s.kind) {
        Some(ServiceKind::Crypto | ServiceKind::Payment) => Confidence::HIGH,
        Some(_) => Confidence::MEDIUM,
        None => Confidence::LOW,
    }
}

pub struct EmailDetector {
    matcher: TextMatcher,
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self {
            matcher: TextMatcher::new(
                r"(?i)[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,10}\b",
            ),
        }
    }
}

impl EmailDetector {
    /// Reject common binary noise such as `x@y.zz` inside compiled code.
    fn plausible(email: &str) -> bool {
        let (local, domain) = email.split_once('@').unwrap_or_default();
        local.len() >= 2 && domain.len() >= 5 && !domain.starts_with('-') && !email.contains("..")
    }
}

impl Detector for EmailDetector {
    fn id(&self) -> &'static str {
        "accounts.email"
    }

    fn max_match(&self) -> usize {
        2 * 160
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.matcher.each(chunk, |off, len, text, wide| {
            if !Self::plausible(text) {
                return;
            }
            let (details, service) = service_details(text, wide);
            sink.emit(
                Hit::new(self.id(), HitCategory::Identity, base + off as u64, len)
                    .label("e-mail")
                    .value(text.to_ascii_lowercase())
                    .confidence(if service.is_some() { confidence_for(service) } else { Confidence::MEDIUM })
                    .details(details),
            );
        });
    }
}

pub struct UrlDetector {
    matcher: TextMatcher,
}

impl Default for UrlDetector {
    fn default() -> Self {
        Self { matcher: TextMatcher::new(r"(?i)\b(?:https?://|www\.)[a-z0-9][a-z0-9.-]{1,253}(?:/[!-~&&[^\s<>]]{0,512})?") }
    }
}

impl Detector for UrlDetector {
    fn id(&self) -> &'static str {
        "accounts.url"
    }

    fn max_match(&self) -> usize {
        2 * 800
    }

    /// Every disk holds millions of generic URLs; only service-classified ones are reported.
    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        self.matcher.each(chunk, |off, len, text, wide| {
            let (details, service) = service_details(text, wide);
            if service.is_none() {
                return;
            }
            sink.emit(
                Hit::new(self.id(), HitCategory::Url, base + off as u64, len)
                    .label(service.map_or("url", |s| s.name))
                    .value(text)
                    .confidence(confidence_for(service))
                    .details(details),
            );
        });
    }
}

pub fn detectors() -> Vec<Arc<dyn Detector>> {
    vec![Arc::new(EmailDetector::default()), Arc::new(UrlDetector::default())]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u8> {
        s.bytes().flat_map(|b| [b, 0]).collect()
    }

    #[test]
    fn email_ascii_and_utf16() {
        let mut data = b"xx login: anna.test3@mail.ru; ".to_vec();
        data.extend(wide("user olga.test1@yandex.ru end"));
        let mut hits = Vec::new();
        EmailDetector::default().scan(&data, 100, &mut hits);
        let values: Vec<_> = hits.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(values, ["anna.test3@mail.ru", "olga.test1@yandex.ru"]);
        assert_eq!(hits[0].offset, 100 + 10);
    }

    #[test]
    fn url_only_reports_known_services() {
        let data = b"see http://example.com/x and https://bitcointalk.org/index.php?topic=1 ok";
        let mut hits = Vec::new();
        UrlDetector::default().scan(data, 0, &mut hits);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "Bitcointalk");
    }
}
