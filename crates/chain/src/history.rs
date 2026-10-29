use serde::{Deserialize, Serialize};
use strata_kernel::Timestamp;

/// One transaction touching an address, from the address's point of view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressTx {
    pub txid: String,
    /// Block time; `None` while unconfirmed.
    pub time: Option<Timestamp>,
    /// Satoshi paid to the address by this transaction.
    pub received_sat: u64,
    /// Satoshi the address spent in this transaction.
    pub sent_sat: u64,
}

/// When an address was used on chain: its transactions (newest first, as the server lists
/// them) and totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressHistory {
    pub address: String,
    pub txs: Vec<AddressTx>,
    /// Confirmed transaction count reported by the server (may exceed `txs.len()`).
    pub tx_count: u64,
    pub total_received_sat: u64,
    /// Every transaction was fetched; otherwise the oldest ones are missing.
    pub complete: bool,
    pub source: String,
}

impl AddressHistory {
    fn times(&self) -> impl Iterator<Item = Timestamp> + '_ {
        self.txs.iter().filter_map(|t| t.time)
    }

    /// Earliest fetched confirmed transaction (the true first one when `complete`).
    pub fn first_seen(&self) -> Option<Timestamp> {
        self.times().min()
    }

    pub fn last_seen(&self) -> Option<Timestamp> {
        self.times().max()
    }

    /// `(time, satoshi)` of every confirmed payment to the address, oldest first.
    pub fn receipts(&self) -> Vec<(Timestamp, u64)> {
        let mut out: Vec<(Timestamp, u64)> = self.txs.iter().filter(|t| t.received_sat > 0).filter_map(|t| Some((t.time?, t.received_sat))).collect();
        out.sort_unstable();
        out
    }

    /// `(time, satoshi)` of every confirmed spend from the address, oldest first.
    pub fn spends(&self) -> Vec<(Timestamp, u64)> {
        let mut out: Vec<(Timestamp, u64)> = self.txs.iter().filter(|t| t.sent_sat > 0).filter_map(|t| Some((t.time?, t.sent_sat))).collect();
        out.sort_unstable();
        out
    }
}
