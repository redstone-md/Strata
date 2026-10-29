//! Most-recently-used lists (`MRUList` letters, `MRUListEx` u32 indices).
//!
//! Only the most recent item of an MRU has a known time (the key's last write); older items
//! become undated facts so they still show up in reports.

use super::hive::{Hive, Key, Value};
use crate::results::Recorder;
use strata_kernel::bytes::u32_le;
use strata_timeline::EventKind;

/// Values of `key` in MRU order (most recent first); unlisted values follow.
pub(crate) fn ordered(hive: &Hive<'_>, key: &Key) -> Vec<Value> {
    let mut values = hive.values(key);
    let order: Vec<String> = if let Some(ex) = values.iter().find(|v| v.name.eq_ignore_ascii_case("MRUListEx")) {
        (0..ex.data.len() / 4)
            .map_while(|i| u32_le(&ex.data, 4 * i))
            .take_while(|i| *i != u32::MAX)
            .map(|i| i.to_string())
            .collect()
    } else if let Some(list) = values.iter().find(|v| v.name.eq_ignore_ascii_case("MRUList")) {
        list.string().unwrap_or_default().chars().map(|c| c.to_string()).collect()
    } else {
        Vec::new()
    };
    values.retain(|v| !v.name.eq_ignore_ascii_case("MRUListEx") && !v.name.eq_ignore_ascii_case("MRUList"));
    let rank = |v: &Value| order.iter().position(|o| o.eq_ignore_ascii_case(&v.name)).unwrap_or(usize::MAX);
    values.sort_by_key(rank);
    values
}

/// First item → event at the key's last write; the rest → facts under `fact_key`.
pub(crate) fn emit(rec: &mut Recorder, key: &Key, items: Vec<String>, kind: EventKind, label: &str, fact_key: &str) {
    let mut items = items.into_iter().filter(|s| !s.trim().is_empty());
    if let Some(first) = items.next() {
        rec.emit(key.last_write, kind, first, format!("{label} (most recent; key last write)"));
    }
    for rest in items {
        rec.fact(fact_key, rest);
    }
}
