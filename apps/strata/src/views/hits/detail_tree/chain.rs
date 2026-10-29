//! Addresses joined with what the chain lookup found. One address node shape for every
//! finding type: the address (copyable) with its on-chain state under it.

use super::node::{Cell, TreeNode};
use crate::format;
use std::collections::HashMap;
use strata_workbench::AddressBalance;

#[derive(Default)]
pub struct Chain {
    by_address: HashMap<String, AddressBalance>,
}

impl Chain {
    pub fn new(balances: impl IntoIterator<Item = AddressBalance>) -> Self {
        Self { by_address: balances.into_iter().map(|b| (b.address.clone(), b)).collect() }
    }

    pub fn used(&self, address: &str) -> bool {
        self.by_address.get(address).is_some_and(AddressBalance::ever_used)
    }

    pub fn cell(&self, address: &str) -> Cell {
        match self.by_address.get(address) {
            Some(b) if b.ever_used() => Cell::Text(format!(
                "{}, {}",
                format::btc(b.balance_sat()),
                format::count(b.tx_count, "transaction", "transactions")
            )),
            Some(_) => Cell::Quiet("never used".into()),
            None => Cell::Quiet("not checked yet".into()),
        }
    }

    /// `label` → address (copyable), opening to its on-chain state and any extra rows.
    pub fn address(&self, label: impl Into<String>, address: &str, extra: Vec<TreeNode>) -> TreeNode {
        let mut children = vec![TreeNode::row("On chain", self.cell(address))];
        children.extend(extra);
        let mut node = TreeNode::group(label, children).summary(Cell::Data(address.to_string())).open_if(self.used(address));
        node.copy = Some(address.to_string());
        node
    }

    /// "n addresses, m used" for a group of addresses.
    pub fn tally<'a>(&self, addresses: impl IntoIterator<Item = &'a str>) -> Cell {
        let (mut n, mut used) = (0u64, 0u64);
        for a in addresses {
            n += 1;
            used += u64::from(self.used(a));
        }
        let text = format!("{}, {used} used", format::count(n, "address", "addresses"));
        if used > 0 { Cell::Text(text) } else { Cell::Quiet(text) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn balance(address: &str, tx: u64) -> AddressBalance {
        AddressBalance {
            address: address.into(),
            funded_sat: 150_000_000 * tx.min(1),
            spent_sat: 0,
            tx_count: tx,
            mempool_delta_sat: 0,
            source: "test".into(),
        }
    }

    #[test]
    fn joins_balances_by_address() {
        let chain = Chain::new([balance("1Used", 3), balance("1Empty", 0)]);
        assert_eq!(chain.cell("1Used"), Cell::Text("1.50000000 BTC, 3 transactions".into()));
        assert_eq!(chain.cell("1Empty"), Cell::Quiet("never used".into()));
        assert_eq!(chain.cell("1Other"), Cell::Quiet("not checked yet".into()));
        assert!(chain.address("P2PKH", "1Used", vec![]).open);
        assert!(!chain.address("P2PKH", "1Other", vec![]).open);
        assert_eq!(chain.tally(["1Used", "1Other"]), Cell::Text("2 addresses, 1 used".into()));
    }
}
