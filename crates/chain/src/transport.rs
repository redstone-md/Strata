//! HTTP GET of JSON documents, behind a trait so backends can be tested with canned pages.

use parking_lot::Mutex;
use std::time::{Duration, Instant};
use strata_kernel::{Error, Result};

pub trait HttpTransport: Send + Sync {
    /// GET `url` and parse the body as JSON.
    fn get_json(&self, url: &str) -> Result<serde_json::Value>;
}

/// ureq client with a polite minimum interval between calls and back-off on HTTP 429 / 503.
pub struct UreqTransport {
    agent: ureq::Agent,
    min_interval: Duration,
    last_call: Mutex<Option<Instant>>,
}

impl UreqTransport {
    pub fn new(min_interval: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .user_agent("strata/0.1")
            .build();
        Self { agent: ureq::Agent::new_with_config(config), min_interval, last_call: Mutex::new(None) }
    }

    fn throttle(&self) {
        let mut last = self.last_call.lock();
        if let Some(t) = *last {
            let wait = self.min_interval.saturating_sub(t.elapsed());
            if !wait.is_zero() {
                std::thread::sleep(wait);
            }
        }
        *last = Some(Instant::now());
    }
}

impl HttpTransport for UreqTransport {
    fn get_json(&self, url: &str) -> Result<serde_json::Value> {
        let mut backoff = Duration::from_secs(2);
        for _ in 0..5 {
            self.throttle();
            match self.agent.get(url).call() {
                Ok(mut resp) => {
                    return resp.body_mut().read_json::<serde_json::Value>().map_err(|e| Error::Other(format!("{url}: {e}")));
                }
                Err(ureq::Error::StatusCode(429 | 503)) => {
                    std::thread::sleep(backoff);
                    backoff *= 2;
                }
                Err(e) => return Err(Error::Other(format!("{url}: {e}"))),
            }
        }
        Err(Error::Other(format!("{url}: rate limited")))
    }
}
