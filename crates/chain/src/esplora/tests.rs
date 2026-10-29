use super::*;
use parking_lot::Mutex;
use serde_json::{Value, json};

const ADDR: &str = "1TestAddrXXXXXXXXXXXXXXXXXXXXXXXXX";
const OTHER: &str = "1OtherAddrXXXXXXXXXXXXXXXXXXXXXXXX";
const T0: i64 = 1_300_000_000;

/// Serves a synthetic address with `n` confirmed txs (newest first) plus one unconfirmed,
/// paginated like Esplora, and records every URL asked for.
struct MockEsplora {
    n: usize,
    calls: Mutex<Vec<String>>,
}

fn tx(i: usize, confirmed: bool) -> Value {
    // Even txs pay the address 1000 sat; odd ones spend 400 of it.
    let (vin, vout) = if i.is_multiple_of(2) {
        (json!([{"prevout": {"scriptpubkey_address": OTHER, "value": 5000}}]), json!([{"scriptpubkey_address": ADDR, "value": 1000}]))
    } else {
        (json!([{"prevout": {"scriptpubkey_address": ADDR, "value": 400}}]), json!([{"scriptpubkey_address": OTHER, "value": 390}]))
    };
    let status = if confirmed { json!({"confirmed": true, "block_time": T0 + i as i64 * 3600}) } else { json!({"confirmed": false}) };
    json!({"txid": format!("tx{i:04}"), "status": status, "vin": vin, "vout": vout})
}

impl HttpTransport for MockEsplora {
    fn get_json(&self, url: &str) -> Result<Value> {
        self.calls.lock().push(url.to_string());
        let path = url.trim_start_matches("https://mock/api");
        let newest_first: Vec<usize> = (0..self.n).rev().collect();
        if path == format!("/address/{ADDR}") {
            return Ok(json!({"chain_stats": {"funded_txo_sum": 30_000, "spent_txo_sum": 12_000, "tx_count": self.n},
                             "mempool_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0, "tx_count": 1}}));
        }
        if path == format!("/address/{ADDR}/txs") {
            let mut page = vec![tx(9999, false)];
            page.extend(newest_first.iter().take(25).map(|i| tx(*i, true)));
            return Ok(Value::Array(page));
        }
        if let Some(last) = path.strip_prefix(&format!("/address/{ADDR}/txs/chain/tx")) {
            let last: usize = last.parse().map_err(|_| strata_kernel::Error::Other("bad txid".into()))?;
            return Ok(Value::Array(newest_first.iter().filter(|i| **i < last).take(25).map(|i| tx(*i, true)).collect()));
        }
        Err(strata_kernel::Error::Other(format!("unexpected {url}")))
    }
}

#[test]
fn history_follows_chain_pages_to_the_first_tx() {
    let mock = Arc::new(MockEsplora { n: 60, calls: Mutex::new(Vec::new()) });
    let backend = EsploraBackend::with_transport("https://mock/api/", mock.clone());
    let h = backend.history(ADDR).unwrap();
    assert!(h.complete);
    assert_eq!(h.txs.len(), 61, "60 confirmed plus the mempool one");
    assert_eq!(h.first_seen().map(|t| t.unix_secs()), Some(T0));
    assert_eq!(h.last_seen().map(|t| t.unix_secs()), Some(T0 + 59 * 3600));
    assert_eq!(h.receipts().len(), 30);
    assert_eq!(h.receipts()[0], (Timestamp::from_unix_secs(T0).unwrap(), 1000));
    assert_eq!(h.spends().len(), 30);
    assert_eq!(h.total_received_sat, 30_000);
    let calls = mock.calls.lock().clone();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[2].ends_with("/txs/chain/tx0035") && calls[3].ends_with("/txs/chain/tx0010"));
}

#[test]
fn short_history_needs_one_page_and_balance_still_works() {
    let mock = Arc::new(MockEsplora { n: 3, calls: Mutex::new(Vec::new()) });
    let backend = EsploraBackend::with_transport("https://mock/api", mock.clone());
    let h = backend.history(ADDR).unwrap();
    assert!(h.complete && h.txs.len() == 4);
    assert_eq!(mock.calls.lock().len(), 2);
    let b = backend.balance(ADDR).unwrap();
    assert_eq!((b.balance_sat(), b.tx_count), (18_000, 4));
}
