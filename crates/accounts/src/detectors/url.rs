use super::{confidence_for, host_char, service_details, url_char};
use crate::service::Service;
use crate::text::expand;
use memchr::memmem::Finder;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

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
    /// disk), so only crypto-relevant services (faucets, exchanges, pools, wallets, forums,
    /// dice, mixers...) and e-money systems are reported.
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
                let Some(service) = Service::classify_url(text).filter(|s| s.kind.is_reportable()) else { continue };
                sink.emit(
                    Hit::new(self.id(), HitCategory::Url, base + span.start as u64, span.raw_len)
                        .label(service.name)
                        .value(text)
                        .confidence(confidence_for(Some(service)))
                        .details(service_details(Some(service), span.wide)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_only_reports_crypto_relevant_services() {
        let data = b"see http://example.com/x http://vk.com/id1 and https://bitcointalk.org/index.php?topic=1 \
                     http://freebitco.in/?r=1 https://www.reddit.com/r/Bitcoin/ https://money.yandex.ru/ ok";
        let mut hits = Vec::new();
        UrlDetector::default().scan(data, 0, &mut hits);
        let mut labels: Vec<_> = hits.iter().map(|h| h.label.as_str()).collect();
        labels.sort_unstable();
        assert_eq!(labels, ["Bitcointalk", "FreeBitco.in", "Reddit crypto subreddits", "Yandex.Money (YooMoney)"]);
        let faucet = hits.iter().find(|h| h.label == "FreeBitco.in").unwrap();
        assert_eq!(faucet.details["service_kind"], "faucet");
    }
}
