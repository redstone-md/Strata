//! Several backends in order of preference. A backend that fails is rested for a while and
//! the next one answers, so one overloaded server does not stall a check of thousands of
//! addresses.

use crate::{AddressBalance, AddressHistory, ChainBackend};
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use strata_kernel::{Error, Result};

/// How long a backend that failed is skipped.
const REST: Duration = Duration::from_secs(60);

pub struct FallbackBackend {
    backends: Vec<Box<dyn ChainBackend>>,
    /// When each backend may be asked again.
    resting: Mutex<Vec<Option<Instant>>>,
    name: String,
}

impl FallbackBackend {
    pub fn new(backends: Vec<Box<dyn ChainBackend>>) -> Self {
        let name = backends.iter().map(|b| b.name()).collect::<Vec<_>>().join(", then ");
        Self { resting: Mutex::new(vec![None; backends.len()]), backends, name }
    }

    /// Ask each backend that is not resting, in order; resting ones are tried last rather
    /// than not at all.
    fn first<T>(&self, ask: impl Fn(&dyn ChainBackend) -> Result<T>) -> Result<T> {
        let now = Instant::now();
        let resting = self.resting.lock().clone();
        let (ready, rested): (Vec<usize>, Vec<usize>) =
            (0..self.backends.len()).partition(|&i| resting[i].is_none_or(|until| until <= now));
        let mut errors = Vec::new();
        for i in ready.into_iter().chain(rested) {
            match ask(self.backends[i].as_ref()) {
                Ok(v) => {
                    self.resting.lock()[i] = None;
                    return Ok(v);
                }
                Err(e) => {
                    self.resting.lock()[i] = Some(Instant::now() + REST);
                    errors.push(e.to_string());
                }
            }
        }
        Err(Error::Other(errors.join("; ")))
    }
}

impl ChainBackend for FallbackBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn balance(&self, address: &str) -> Result<AddressBalance> {
        self.first(|b| b.balance(address))
    }

    fn history(&self, address: &str) -> Result<AddressHistory> {
        self.first(|b| b.history(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake {
        name: &'static str,
        up: bool,
        calls: Arc<AtomicUsize>,
    }

    impl ChainBackend for Fake {
        fn name(&self) -> &str {
            self.name
        }

        fn balance(&self, address: &str) -> Result<AddressBalance> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if !self.up {
                return Err(Error::Other("overloaded".into()));
            }
            Ok(AddressBalance { address: address.into(), funded_sat: 5, spent_sat: 0, tx_count: 1, mempool_delta_sat: 0, source: self.name.into() })
        }
    }

    #[test]
    fn a_failing_backend_rests_while_the_next_answers() {
        let (main, spare) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let chain = FallbackBackend::new(vec![
            Box::new(Fake { name: "main", up: false, calls: main.clone() }),
            Box::new(Fake { name: "spare", up: true, calls: spare.clone() }),
        ]);
        for _ in 0..5 {
            assert_eq!(chain.balance("1x").unwrap().source, "spare");
        }
        assert_eq!(main.load(Ordering::Relaxed), 1, "the failed backend is not asked again while resting");
        assert_eq!(spare.load(Ordering::Relaxed), 5);
        assert_eq!(chain.name(), "main, then spare");
    }

    #[test]
    fn all_failing_reports_every_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let chain = FallbackBackend::new(vec![Box::new(Fake { name: "a", up: false, calls })]);
        assert!(chain.balance("1x").is_err());
    }
}
