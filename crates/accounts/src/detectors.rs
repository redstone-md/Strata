use crate::service::{Service, ServiceKind};
use crate::text::{expand, stride_at};
use memchr::memchr_iter;
use memchr::memmem::Finder;
use std::sync::Arc;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

/// Characters allowed in each part (ASCII view).
fn local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn host_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

fn url_char(c: u8) -> bool {
    c.is_ascii_graphic() && !matches!(c, b'<' | b'>' | b'"' | b'\'' | b'`')
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

/// Finds `@` with memchr and expands around it (ASCII or UTF-16LE).
#[derive(Default)]
pub struct EmailDetector;

/// Top-level domains seen on old disks. Used to cut addresses glued to following text
/// (`user@mail.rupass` -> `user@mail.ru`).
const KNOWN_TLDS: &[&str] = &[
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "name", "mobi", "ru", "su", "ua", "by", "kz", "uz",
    "md", "am", "az", "ge", "lv", "lt", "ee", "de", "uk", "fr", "it", "es", "pl", "cz", "nl", "be", "ch", "at",
    "se", "no", "fi", "dk", "il", "tr", "us", "ca", "au", "jp", "cn", "in", "br", "tv", "cc", "ws", "io", "me",
];

impl EmailDetector {
    /// Trim a glued tail off the TLD and reject binary noise. Returns the cleaned address.
    fn clean(email: &str) -> Option<String> {
        let lower = email.to_ascii_lowercase();
        let (local, domain) = lower.split_once('@')?;
        let (host, tld) = domain.rsplit_once('.')?;
        let tld = if KNOWN_TLDS.contains(&tld) {
            tld
        } else {
            KNOWN_TLDS.iter().filter(|t| tld.starts_with(*t)).max_by_key(|t| t.len())?
        };
        let domain = format!("{host}.{tld}");
        let plausible = local.len() >= 2 && domain.len() >= 5 && !domain.starts_with('-') && !lower.contains("..");
        plausible.then(|| format!("{local}@{domain}"))
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
        for at in memchr_iter(b'@', chunk) {
            let span = expand(chunk, at, stride_at(chunk, at), 128, local_char, host_char);
            let Some(email) = Self::clean(span.text.trim_matches(['.', '-'])) else { continue };
            let (details, service) = service_details(&email, span.wide);
            sink.emit(
                Hit::new(self.id(), HitCategory::Identity, base + span.start as u64, span.raw_len)
                    .label("e-mail")
                    .value(email)
                    .confidence(if service.is_some() { confidence_for(service) } else { Confidence::MEDIUM })
                    .details(details),
            );
        }
    }
}

/// URL starts, matched in ASCII and UTF-16LE, upper and lower case.
const URL_ANCHORS: &[&str] = &["http://", "https://", "www.", "HTTP://", "HTTPS://", "WWW."];

pub struct UrlDetector {
    /// `(finder, stride)`: stride 2 for the UTF-16LE form of an anchor.
    finders: Vec<(Finder<'static>, usize)>,
}

impl Default for UrlDetector {
    fn default() -> Self {
        let mut finders = Vec::new();
        for a in URL_ANCHORS {
            finders.push((Finder::new(a.as_bytes()).into_owned(), 1));
            let wide: Vec<u8> = a.bytes().flat_map(|b| [b, 0]).collect();
            finders.push((Finder::new(&wide).into_owned(), 2));
        }
        Self { finders }
    }
}

impl Detector for UrlDetector {
    fn id(&self) -> &'static str {
        "accounts.url"
    }

    fn max_match(&self) -> usize {
        2 * 800
    }

    /// Every disk holds millions of generic URLs (social sites alone gave 5M hits on a 40 GB
    /// disk), so only crypto and payment services are reported, matched on the host.
    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        for (finder, stride) in &self.finders {
            for at in finder.find_iter(chunk) {
                // `www.` right after `://` belongs to a URL its scheme anchor already reported.
                let before = at.checked_sub(*stride).and_then(|i| chunk.get(i));
                if before == Some(&b'/') {
                    continue;
                }
                // Expand right only: the anchor is the start of the URL.
                let span = expand(chunk, at, *stride, 800, |_| false, url_char);
                let text = span.text.as_str();
                let host = text.split("://").last().unwrap_or(text).split(['/', '?', '#', ':']).next().unwrap_or_default();
                if !host.bytes().all(host_char) || !host.contains('.') {
                    continue;
                }
                let (details, service) = service_details(host, span.wide);
                if !matches!(service.map(|s| s.kind), Some(ServiceKind::Crypto | ServiceKind::Payment)) {
                    continue;
                }
                sink.emit(
                    Hit::new(self.id(), HitCategory::Url, base + span.start as u64, span.raw_len)
                        .label(service.map_or("url", |s| s.name))
                        .value(text)
                        .confidence(confidence_for(service))
                        .details(details),
                );
            }
        }
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
        let mut glued = Vec::new();
        EmailDetector::default().scan(b"emailivan.test2@mail.rupasshttp", 0, &mut glued);
        assert_eq!(glued[0].value, "emailivan.test2@mail.ru");
        assert_eq!(hits[0].offset, 100 + 10);
    }

    #[test]
    fn url_only_reports_known_services() {
        let data = b"see http://example.com/x http://vk.com/id1 and https://bitcointalk.org/index.php?topic=1 ok";
        let mut hits = Vec::new();
        UrlDetector::default().scan(data, 0, &mut hits);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].label, "Bitcointalk");
    }
}
