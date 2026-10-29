//! On-chain balances of every found or derived address, then the transaction histories of
//! used addresses, then accounts and leads rebuilt from everything the case holds. Three
//! checkpointed phases; the first two are idempotent by construction (only addresses without
//! a stored lookup or history are fetched), lookups commit in batches.

use crate::insights::Insights;
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_chain::{AddressBalance, ChainBackend, EsploraBackend};
use strata_kernel::Result;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    #[default]
    Balances,
    Histories,
    Insights,
    Done,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BalancesCursor {
    #[serde(default)]
    phase: Phase,
    checked: usize,
    used: usize,
    failed: usize,
    #[serde(default)]
    histories: usize,
    #[serde(default)]
    accounts: usize,
    #[serde(default)]
    leads: usize,
}

impl Cursor for BalancesCursor {
    fn note(&self) -> String {
        match self.phase {
            Phase::Balances => format!("the next unchecked address ({} checked so far)", self.checked),
            Phase::Histories => "address histories not fetched yet".into(),
            Phase::Insights => "rebuilding accounts and leads".into(),
            Phase::Done => "nothing left".into(),
        }
    }
}

/// Look up every unchecked address; false when stopped part-way.
fn lookups(ctx: &StepContext<'_>, backend: &dyn ChainBackend, cur: &mut BalancesCursor) -> Result<bool> {
    let addresses = ctx.case().unchecked_addresses()?;
    ctx.control().begin_at(cur.checked as u64, (cur.checked + addresses.len()) as u64);
    let mut batch: Vec<AddressBalance> = Vec::new();
    for a in &addresses {
        if ctx.should_stop() {
            ctx.commit(cur, |w| batch.iter().try_for_each(|b| w.balance(b)))?;
            return Ok(false);
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
            ctx.commit(cur, |w| found.iter().try_for_each(|b| w.balance(b)))?;
        }
    }
    cur.phase = Phase::Histories;
    ctx.commit(cur, |w| batch.iter().try_for_each(|b| w.balance(b)))?;
    ctx.log(format!("{} addresses checked, {} used on chain", cur.checked, cur.used));
    Ok(true)
}

pub(super) fn run(ctx: &StepContext<'_>, endpoint: &str) -> Result<String> {
    let backend = EsploraBackend::new(endpoint);
    let insights = Insights::new(ctx.case());
    let mut cur: BalancesCursor = ctx.cursor().unwrap_or_default();
    if cur.phase == Phase::Balances && !lookups(ctx, &backend, &mut cur)? {
        return Ok(String::new());
    }
    if cur.phase == Phase::Histories {
        let (fetched, failed) = insights.fetch_histories(&backend, ctx.control())?;
        if ctx.should_stop() {
            return Ok(String::new());
        }
        cur.histories += fetched;
        cur.phase = Phase::Insights;
        ctx.commit(&cur, |_| Ok(()))?;
        ctx.log(format!("{fetched} address histories fetched, {failed} failed"));
    }
    if cur.phase == Phase::Insights {
        ctx.current("accounts and leads");
        let (accounts, leads) = insights.rebuild()?;
        (cur.accounts, cur.leads, cur.phase) = (accounts, leads, Phase::Done);
        ctx.commit(&cur, |_| Ok(()))?;
        ctx.log(format!("{accounts} accounts, {leads} leads"));
    }
    Ok(format!(
        "{} addresses, {} used on chain, {} lookups failed; {} histories; {} accounts, {} leads",
        cur.checked, cur.used, cur.failed, cur.histories, cur.accounts, cur.leads
    ))
}
