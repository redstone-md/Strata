//! On-chain balances of every found or derived address. Idempotent by construction: only
//! addresses without a stored lookup are checked, and lookups commit in batches.

use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_chain::{AddressBalance, ChainBackend, EsploraBackend};
use strata_kernel::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
struct BalancesCursor {
    checked: usize,
    used: usize,
    failed: usize,
}

impl Cursor for BalancesCursor {
    fn note(&self) -> String {
        format!("the next unchecked address ({} checked so far)", self.checked)
    }
}

pub(super) fn run(ctx: &StepContext<'_>, endpoint: &str) -> Result<String> {
    let addresses = ctx.case().unchecked_addresses()?;
    let backend = EsploraBackend::new(endpoint);
    let mut cur: BalancesCursor = ctx.cursor().unwrap_or_default();
    ctx.control().begin_at(cur.checked as u64, (cur.checked + addresses.len()) as u64);
    let mut batch: Vec<AddressBalance> = Vec::new();
    for a in &addresses {
        if ctx.should_stop() {
            break;
        }
        ctx.current(a);
        match backend.balance(a) {
            Ok(b) => {
                cur.used += usize::from(b.ever_used());
                batch.push(b);
            }
            Err(_) => cur.failed += 1,
        }
        cur.checked += 1;
        ctx.control().item_done();
        if ctx.tick(1) {
            let found = std::mem::take(&mut batch);
            ctx.commit(&cur, |w| found.iter().try_for_each(|b| w.balance(b)))?;
        }
    }
    ctx.commit(&cur, |w| batch.iter().try_for_each(|b| w.balance(b)))?;
    ctx.log(format!("{} addresses checked, {} used on chain", cur.checked, cur.used));
    Ok(format!("{} addresses, {} used on chain, {} lookups failed", cur.checked, cur.used, cur.failed))
}
