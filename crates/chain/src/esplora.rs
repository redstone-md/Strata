use crate::{AddressBalance, ChainBackend};
use parking_lot::Mutex;
use serde::Deserialize;
use std::time::{Duration, Instant};
use strata_kernel::{Error, Result};

#[derive(Deserialize)]
struct Stats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
    tx_count: u64,
}

#[derive(Deserialize)]
struct AddressInfo {
    chain_stats: Stats,
    mempool_stats: Stats,
}

/// Esplora REST client with a polite rate limit and retry on HTTP 429.
pub struct EsploraBackend {
    base: String,
    agent: ureq::Agent,
    min_interval: Duration,
    last_call: Mutex<Option<Instant>>,
}

impl EsploraBackend {
    pub const MEMPOOL_SPACE: &'static str = "https://mempool.space/api";
    pub const BLOCKSTREAM: &'static str = "https://blockstream.info/api";

    pub fn new(base: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .user_agent("strata/0.1")
            .build();
        Self {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::Agent::new_with_config(config),
            min_interval: Duration::from_millis(300),
            last_call: Mutex::new(None),
        }
    }

    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
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

    fn fetch(&self, address: &str) -> Result<AddressInfo> {
        let url = format!("{}/address/{}", self.base, address);
        let mut backoff = Duration::from_secs(2);
        for _ in 0..5 {
            self.throttle();
            match self.agent.get(&url).call() {
                Ok(mut resp) => {
                    return resp.body_mut().read_json::<AddressInfo>().map_err(|e| Error::Other(format!("{url}: {e}")));
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

impl ChainBackend for EsploraBackend {
    fn name(&self) -> &str {
        &self.base
    }

    fn balance(&self, address: &str) -> Result<AddressBalance> {
        let info = self.fetch(address)?;
        let m = &info.mempool_stats;
        Ok(AddressBalance {
            address: address.to_string(),
            funded_sat: info.chain_stats.funded_txo_sum,
            spent_sat: info.chain_stats.spent_txo_sum,
            tx_count: info.chain_stats.tx_count + m.tx_count,
            mempool_delta_sat: m.funded_txo_sum as i64 - m.spent_txo_sum as i64,
            source: self.base.clone(),
        })
    }
}
