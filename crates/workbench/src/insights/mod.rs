//! Accounts and leads: rebuilt from everything the case knows after each analysis step that
//! adds findings, events or chain data. Also fetches on-chain histories of used addresses.

mod accounts;

use accounts::AccountsBuilder;
use strata_case::Case;
use strata_chain::ChainBackend;
use strata_engine::ScanControl;
use strata_kernel::Result;
use strata_leads::{LeadEngine, LeadInputs};

/// Timeline events read per rebuild (crypto- and account-related only).
const MAX_EVENTS: usize = 500_000;
/// Key findings below this confidence are left out of leads.
const MIN_KEY_CONFIDENCE: f32 = 0.3;

pub(crate) struct Insights<'a> {
    case: &'a Case,
}

impl<'a> Insights<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Resolve accounts, run the lead engine, store both. Returns `(accounts, leads)`.
    pub fn rebuild(&self) -> Result<(usize, usize)> {
        let events = self.case.lead_events(MAX_EVENTS)?;
        let accounts = AccountsBuilder::build(self.case, &events)?;
        let stored_accounts = self.case.replace_accounts(&accounts)?;
        let inputs = LeadInputs { keys: self.case.key_findings(MIN_KEY_CONFIDENCE)?, histories: self.case.histories()?, events, accounts };
        let mut leads = LeadEngine::new().run(&inputs);
        // Wallet trails rank among the leads; the trails screen lists them all.
        leads.extend(crate::trails::leads(&crate::trails::build(self.case)?));
        leads.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        Ok((stored_accounts, self.case.replace_leads(&leads)?))
    }

    /// Fetch and cache the transaction history of every used address that has none yet.
    /// Returns `(fetched, failed)`.
    pub fn fetch_histories(&self, backend: &dyn ChainBackend, control: &ScanControl) -> Result<(usize, usize)> {
        let addresses = self.case.addresses_without_history()?;
        control.begin_items(addresses.len() as u64);
        let (mut fetched, mut failed) = (0, 0);
        for a in &addresses {
            if control.should_stop() {
                break;
            }
            control.set_current(a);
            match backend.history(a) {
                Ok(h) => {
                    self.case.store_history(&h)?;
                    fetched += 1;
                }
                Err(_) => failed += 1,
            }
            control.item_done();
        }
        Ok((fetched, failed))
    }
}

impl crate::Workbench {
    /// Resolved accounts, fund-holding services first (rebuilt by [`Self::rebuild_insights`]).
    pub fn accounts(&self) -> Result<Vec<strata_accounts::Account>> {
        self.case().accounts()
    }

    /// Ranked leads, best first.
    pub fn leads(&self) -> Result<Vec<strata_leads::Lead>> {
        self.case().leads()
    }

    /// Cached on-chain history of one address.
    pub fn address_history(&self, address: &str) -> Result<Option<strata_chain::AddressHistory>> {
        self.case().history_of(address)
    }

    /// The findings a lead points at.
    pub fn lead_hits(&self, lead: &strata_leads::Lead) -> Result<Vec<strata_case::StoredHit>> {
        let ids: Vec<i64> = lead.hits().collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.case().hits(&strata_case::HitQuery { ids, ..Default::default() })
    }

    /// The timeline events a lead points at, oldest first.
    pub fn lead_events(&self, lead: &strata_leads::Lead) -> Result<Vec<strata_leads::EventRecord>> {
        self.case().events_by_id(&lead.events().collect::<Vec<_>>())
    }

    /// Re-resolve accounts and re-run the lead engine on what the case holds now. Returns
    /// `(accounts, leads)`. Also runs at the end of the balance check.
    pub fn rebuild_insights(&self) -> Result<(usize, usize)> {
        Insights::new(self.case()).rebuild()
    }

    /// Fetch missing on-chain histories of used addresses from the configured endpoint, then
    /// rebuild. Returns `(fetched, failed)`.
    pub fn fetch_histories(&self) -> Result<(usize, usize)> {
        let backend = strata_chain::EsploraBackend::new(&self.chain_endpoint());
        let fetched = Insights::new(self.case()).fetch_histories(&backend, &ScanControl::default())?;
        self.rebuild_insights()?;
        Ok(fetched)
    }
}
