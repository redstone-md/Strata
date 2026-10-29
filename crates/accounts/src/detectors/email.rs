use super::{confidence_for, host_char, service_details};
use crate::service::Service;
use crate::text::{expand, stride_at};
use memchr::memchr_iter;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

fn local_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-')
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
            let service = Service::classify_email(&email);
            sink.emit(
                Hit::new(self.id(), HitCategory::Identity, base + span.start as u64, span.raw_len)
                    .label("e-mail")
                    .value(email)
                    .confidence(if service.is_some() { confidence_for(service) } else { Confidence::MEDIUM })
                    .details(service_details(service, span.wide)),
            );
        }
    }
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
        EmailDetector.scan(&data, 100, &mut hits);
        let values: Vec<_> = hits.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(values, ["anna.test3@mail.ru", "olga.test1@yandex.ru"]);
        assert_eq!(hits[0].details["service_id"], "mailru");
        let mut glued = Vec::new();
        EmailDetector.scan(b"emailivan.test2@mail.rupasshttp", 0, &mut glued);
        assert_eq!(glued[0].value, "emailivan.test2@mail.ru");
        assert_eq!(hits[0].offset, 100 + 10);
    }
}
