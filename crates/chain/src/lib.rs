//! Chain context: is an address (and therefore a recovered key) worth anything, and when was
//! it used?
//!
//! Backends sit behind [`ChainBackend`]; [`EsploraBackend`] talks to any Esplora REST server
//! (mempool.space, blockstream.info, or the user's own instance). [`FallbackBackend`] chains
//! it with the public balance services ([`BlockchainInfoBackend`], [`BlockCypherBackend`]) for
//! when it is overloaded.

mod balance;
mod esplora;
mod extract;
mod fallback;
mod history;
mod public;
mod transport;

pub use balance::AddressBalance;
pub use esplora::EsploraBackend;
pub use extract::addresses_in;
pub use fallback::FallbackBackend;
pub use history::{AddressHistory, AddressTx};
pub use public::{BlockCypherBackend, BlockchainInfoBackend};
pub use transport::{HttpTransport, UreqTransport};

use strata_kernel::{Error, Result};

pub trait ChainBackend: Send + Sync {
    fn name(&self) -> &str;
    fn balance(&self, address: &str) -> Result<AddressBalance>;

    /// Transactions of an address (when they happened, what was received and spent).
    fn history(&self, address: &str) -> Result<AddressHistory> {
        Err(Error::Other(format!("{}: no transaction history for {address}", self.name())))
    }
}
