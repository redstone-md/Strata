//! Public balance services used when the main Esplora server is overloaded: blockchain.info
//! and BlockCypher. They answer balances only; transaction histories stay with Esplora.

use crate::transport::{HttpTransport, UreqTransport};
use crate::{AddressBalance, ChainBackend};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use strata_kernel::{Error, Result};

/// `blockchain.info/balance?active=<address>`: received, final balance and transaction count.
pub struct BlockchainInfoBackend {
    base: String,
    transport: Arc<dyn HttpTransport>,
}

#[derive(Deserialize)]
struct InfoEntry {
    final_balance: u64,
    n_tx: u64,
    total_received: u64,
}

impl BlockchainInfoBackend {
    pub const URL: &'static str = "https://blockchain.info";

    pub fn new() -> Self {
        Self::with_transport(Self::URL, Arc::new(UreqTransport::new(Duration::from_millis(500))))
    }

    pub fn with_transport(base: &str, transport: Arc<dyn HttpTransport>) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), transport }
    }
}

impl Default for BlockchainInfoBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainBackend for BlockchainInfoBackend {
    fn name(&self) -> &str {
        &self.base
    }

    fn balance(&self, address: &str) -> Result<AddressBalance> {
        let url = format!("{}/balance?active={address}", self.base);
        let mut all: HashMap<String, InfoEntry> =
            serde_json::from_value(self.transport.get_json(&url)?).map_err(|e| Error::Other(format!("{url}: {e}")))?;
        let e = all.remove(address).ok_or_else(|| Error::Other(format!("{url}: address missing from the answer")))?;
        Ok(AddressBalance {
            address: address.to_string(),
            funded_sat: e.total_received,
            spent_sat: e.total_received.saturating_sub(e.final_balance),
            tx_count: e.n_tx,
            mempool_delta_sat: 0,
            source: self.base.clone(),
        })
    }
}

/// `api.blockcypher.com/v1/btc/main/addrs/<address>/balance`.
pub struct BlockCypherBackend {
    base: String,
    transport: Arc<dyn HttpTransport>,
}

#[derive(Deserialize)]
struct CypherBalance {
    total_received: u64,
    total_sent: u64,
    #[serde(default)]
    n_tx: u64,
    #[serde(default)]
    unconfirmed_balance: i64,
}

impl BlockCypherBackend {
    pub const URL: &'static str = "https://api.blockcypher.com/v1/btc/main";

    /// The free tier allows a few calls per second.
    pub fn new() -> Self {
        Self::with_transport(Self::URL, Arc::new(UreqTransport::new(Duration::from_millis(400))))
    }

    pub fn with_transport(base: &str, transport: Arc<dyn HttpTransport>) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), transport }
    }
}

impl Default for BlockCypherBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainBackend for BlockCypherBackend {
    fn name(&self) -> &str {
        &self.base
    }

    fn balance(&self, address: &str) -> Result<AddressBalance> {
        let url = format!("{}/addrs/{address}/balance", self.base);
        let b: CypherBalance = serde_json::from_value(self.transport.get_json(&url)?).map_err(|e| Error::Other(format!("{url}: {e}")))?;
        Ok(AddressBalance {
            address: address.to_string(),
            funded_sat: b.total_received,
            spent_sat: b.total_sent,
            tx_count: b.n_tx,
            mempool_delta_sat: b.unconfirmed_balance,
            source: self.base.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    struct Canned(Value);

    impl HttpTransport for Canned {
        fn get_json(&self, _: &str) -> Result<Value> {
            Ok(self.0.clone())
        }
    }

    const ADDR: &str = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";

    #[test]
    fn blockchain_info_balance() {
        let answer = json!({ ADDR: { "final_balance": 300, "n_tx": 4, "total_received": 1000 } });
        let b = BlockchainInfoBackend::with_transport("https://x", Arc::new(Canned(answer))).balance(ADDR).unwrap();
        assert_eq!((b.funded_sat, b.spent_sat, b.tx_count, b.balance_sat()), (1000, 700, 4, 300));
    }

    #[test]
    fn blockcypher_balance() {
        let answer = json!({ "address": ADDR, "total_received": 1000, "total_sent": 1000, "balance": 0, "n_tx": 2, "unconfirmed_balance": 0 });
        let b = BlockCypherBackend::with_transport("https://x", Arc::new(Canned(answer))).balance(ADDR).unwrap();
        assert_eq!((b.funded_sat, b.spent_sat, b.tx_count, b.balance_sat()), (1000, 1000, 2, 0));
    }
}
