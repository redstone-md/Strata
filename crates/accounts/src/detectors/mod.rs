//! Byte-level identity detectors: e-mail addresses, service URLs and login values. Each finds
//! a rare anchor first and classifies only what it found, so the catalogue size does not
//! slow the scan.

mod email;
mod login;
mod url;

pub use email::EmailDetector;
pub use login::LoginDetector;
pub use url::UrlDetector;

use crate::service::Service;
use std::sync::Arc;
use strata_kernel::Confidence;
use strata_kernel::scan::Detector;

/// Characters of a URL token (ASCII view).
pub(crate) fn url_char(c: u8) -> bool {
    c.is_ascii_graphic() && !matches!(c, b'<' | b'>' | b'"' | b'\'' | b'`')
}

pub(crate) fn host_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-')
}

/// `details` shared by every identity hit: encoding plus the classified service.
pub(crate) fn service_details(service: Option<Service>, wide: bool) -> serde_json::Value {
    serde_json::json!({
        "encoding": if wide { "utf-16le" } else { "ascii" },
        "service": service.map(|s| s.name),
        "service_id": service.map(|s| s.id),
        "service_kind": service.map(|s| s.kind.label()),
    })
}

/// Crypto and payment services are direct leads; other known services are context.
pub(crate) fn confidence_for(service: Option<Service>) -> Confidence {
    match service.map(|s| s.kind) {
        Some(k) if k.is_reportable() => Confidence::HIGH,
        Some(_) => Confidence::MEDIUM,
        None => Confidence::LOW,
    }
}

pub fn detectors() -> Vec<Arc<dyn Detector>> {
    vec![Arc::new(EmailDetector), Arc::new(UrlDetector::default()), Arc::new(LoginDetector::default())]
}
