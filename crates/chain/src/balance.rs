use serde::{Deserialize, Serialize};

/// On-chain state of one address, in satoshi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBalance {
    pub address: String,
    pub funded_sat: u64,
    pub spent_sat: u64,
    pub tx_count: u64,
    /// Unconfirmed delta (can be negative).
    pub mempool_delta_sat: i64,
    pub source: String,
}

impl AddressBalance {
    pub fn balance_sat(&self) -> u64 {
        self.funded_sat.saturating_sub(self.spent_sat)
    }

    /// The address appeared on chain at least once — the key was really used.
    pub fn ever_used(&self) -> bool {
        self.tx_count > 0
    }

    pub fn balance_btc(&self) -> f64 {
        self.balance_sat() as f64 / 1e8
    }
}
