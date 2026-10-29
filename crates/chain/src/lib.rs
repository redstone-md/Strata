//! Chain context: is an address (and therefore a recovered key) worth anything?
//!
//! Backends sit behind [`ChainBackend`]; [`EsploraBackend`] talks to any Esplora REST server
//! (mempool.space, blockstream.info, or the user's own instance).

mod balance;
mod esplora;
mod extract;

pub use balance::AddressBalance;
pub use esplora::EsploraBackend;
pub use extract::addresses_in;

use strata_kernel::Result;

pub trait ChainBackend: Send + Sync {
    fn name(&self) -> &str;
    fn balance(&self, address: &str) -> Result<AddressBalance>;
}
