use crate::transport::{HttpTransport, UreqTransport};
use crate::{AddressBalance, AddressHistory, AddressTx, ChainBackend};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use strata_kernel::{Error, Result, Timestamp};

/// Confirmed transactions per Esplora page.
const PAGE: usize = 25;
/// Pages fetched per address (1 000 transactions); busier addresses are marked incomplete.
const MAX_PAGES: usize = 40;

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

#[derive(Deserialize, Default)]
struct Status {
    #[serde(default)]
    confirmed: bool,
    block_time: Option<i64>,
}

#[derive(Deserialize)]
struct Output {
    scriptpubkey_address: Option<String>,
    #[serde(default)]
    value: u64,
}

#[derive(Deserialize)]
struct Input {
    prevout: Option<Output>,
}

#[derive(Deserialize)]
struct Tx {
    txid: String,
    #[serde(default)]
    status: Status,
    #[serde(default)]
    vin: Vec<Input>,
    #[serde(default)]
    vout: Vec<Output>,
}

impl Tx {
    fn for_address(&self, address: &str) -> AddressTx {
        let mine = |o: &&Output| o.scriptpubkey_address.as_deref() == Some(address);
        AddressTx {
            txid: self.txid.clone(),
            time: self.status.block_time.filter(|_| self.status.confirmed).and_then(Timestamp::from_unix_secs),
            received_sat: self.vout.iter().filter(mine).map(|o| o.value).sum(),
            sent_sat: self.vin.iter().filter_map(|i| i.prevout.as_ref()).filter(mine).map(|o| o.value).sum(),
        }
    }
}

/// Esplora REST client (mempool.space, blockstream.info or the user's own instance).
pub struct EsploraBackend {
    base: String,
    transport: Arc<dyn HttpTransport>,
}

impl EsploraBackend {
    pub const MEMPOOL_SPACE: &'static str = "https://mempool.space/api";
    pub const BLOCKSTREAM: &'static str = "https://blockstream.info/api";

    /// Live client, at most one request per 300 ms.
    pub fn new(base: &str) -> Self {
        Self::with_transport(base, Arc::new(UreqTransport::new(Duration::from_millis(300))))
    }

    pub fn with_transport(base: &str, transport: Arc<dyn HttpTransport>) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), transport }
    }

    pub fn with_min_interval(self, interval: Duration) -> Self {
        Self::with_transport(&self.base, Arc::new(UreqTransport::new(interval)))
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base);
        serde_json::from_value(self.transport.get_json(&url)?).map_err(|e| Error::Other(format!("{url}: {e}")))
    }

    fn info(&self, address: &str) -> Result<AddressInfo> {
        self.get(&format!("/address/{address}"))
    }
}

impl ChainBackend for EsploraBackend {
    fn name(&self) -> &str {
        &self.base
    }

    fn balance(&self, address: &str) -> Result<AddressBalance> {
        let info = self.info(address)?;
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

    /// `/address/:a/txs` (mempool + newest confirmed), then `/txs/chain/:last_txid` pages of
    /// 25 until a short page, up to [`MAX_PAGES`].
    fn history(&self, address: &str) -> Result<AddressHistory> {
        let info = self.info(address)?;
        let mut txs: Vec<AddressTx> = Vec::new();
        let mut page: Vec<Tx> = self.get(&format!("/address/{address}/txs"))?;
        let mut complete = false;
        for round in 1.. {
            let confirmed = page.iter().filter(|t| t.status.confirmed).count();
            let last_confirmed = page.iter().rev().find(|t| t.status.confirmed).map(|t| t.txid.clone());
            for t in &page {
                if !txs.iter().any(|x| x.txid == t.txid) {
                    txs.push(t.for_address(address));
                }
            }
            let fetched = txs.iter().filter(|t| t.time.is_some()).count() as u64;
            let (true, Some(last)) = (confirmed >= PAGE && fetched < info.chain_stats.tx_count, last_confirmed) else {
                complete = true;
                break;
            };
            if round >= MAX_PAGES {
                break;
            }
            page = self.get(&format!("/address/{address}/txs/chain/{last}"))?;
        }
        Ok(AddressHistory {
            address: address.to_string(),
            txs,
            tx_count: info.chain_stats.tx_count,
            total_received_sat: info.chain_stats.funded_txo_sum,
            complete,
            source: self.base.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
