//! `cargo run -p strata-chain --example balance -- <address>`
use strata_chain::{ChainBackend, EsploraBackend};

fn main() {
    let addr = std::env::args().nth(1).expect("usage: balance <address>");
    let b = EsploraBackend::new(EsploraBackend::MEMPOOL_SPACE).balance(&addr).expect("lookup");
    println!("{b:?} balance {} BTC used {}", b.balance_btc(), b.ever_used());
}
