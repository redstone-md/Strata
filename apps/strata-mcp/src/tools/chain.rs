//! On-chain data the balance check stored: per-address balances and cached transaction
//! histories. Nothing is fetched from the network here.

use super::findings::Balance;
use crate::StrataServer;
use crate::format::{Page, Paging, Reply, btc, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{AddressHistory, Workbench};

/// Which looked-up addresses to list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BalanceFilter {
    /// Every address the balance check looked up, unused ones included.
    All,
    /// Addresses with at least one transaction (the key was really used).
    #[default]
    Used,
    /// Addresses that hold coins now.
    Funded,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BalancesParams {
    /// Default `used`.
    pub filter: BalanceFilter,
    /// Part of the address.
    pub text: Option<String>,
    /// Rows per page, default 100, at most 1000.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressHistoryParams {
    pub address: String,
    /// Transactions per page, default 100, at most 1000, oldest first.
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Serialize)]
struct History {
    address: String,
    tx_count: u64,
    total_received_sat: u64,
    total_received_btc: String,
    first_seen: Option<String>,
    last_seen: Option<String>,
    /// All transactions were fetched.
    complete: bool,
    source: String,
    transactions: Page<Tx>,
}

#[derive(Serialize)]
struct Tx {
    txid: String,
    time: Option<String>,
    received_sat: u64,
    sent_sat: u64,
}

fn balances(wb: &Workbench, p: BalancesParams) -> Reply<Page<Balance>> {
    let needle = p.text.unwrap_or_default().to_lowercase();
    let rows: Vec<Balance> = wb
        .balances()
        .map_err(fail)?
        .iter()
        .filter(|b| match p.filter {
            BalanceFilter::All => true,
            BalanceFilter::Used => b.tx_count > 0,
            BalanceFilter::Funded => b.balance_sat() > 0,
        })
        .filter(|b| needle.is_empty() || b.address.to_lowercase().contains(&needle))
        .map(Balance::of)
        .collect();
    Ok(Page::slice(rows, p.offset, Paging::LONG.limit(p.limit)))
}

fn history(wb: &Workbench, p: AddressHistoryParams) -> Reply<History> {
    let h: AddressHistory = wb
        .address_history(p.address.trim())
        .map_err(fail)?
        .ok_or_else(|| format!("no cached history for {}; histories exist only for used addresses the app fetched", p.address))?;
    let txs = h.txs.iter().map(|t| Tx { txid: t.txid.clone(), time: t.time.map(time), received_sat: t.received_sat, sent_sat: t.sent_sat }).collect();
    Ok(History {
        address: h.address.clone(),
        tx_count: h.tx_count,
        total_received_sat: h.total_received_sat,
        total_received_btc: btc(h.total_received_sat),
        first_seen: h.first_seen().map(time),
        last_seen: h.last_seen().map(time),
        complete: h.complete,
        source: h.source.clone(),
        transactions: Page::slice(txs, p.offset, Paging::LONG.limit(p.limit)),
    })
}

#[tool_router(router = chain_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "On-chain balances of addresses found on the disks or derived from found keys, seeds and wallets, as \
        stored by the app's balance check: balance, funded, spent, transaction count. Richest first. Default: only used \
        addresses (at least one transaction)."
    )]
    pub async fn balances(&self, Parameters(p): Parameters<BalancesParams>) -> Reply<String> {
        self.query(move |wb| balances(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Cached on-chain transaction history of one address (time, received, sent per transaction; first and \
        last activity). Exists for used addresses whose history the app fetched; use with `timeline` to see what the user \
        did around those dates."
    )]
    pub async fn address_history(&self, Parameters(p): Parameters<AddressHistoryParams>) -> Reply<String> {
        self.query(move |wb| history(wb, p)).await
    }
}
