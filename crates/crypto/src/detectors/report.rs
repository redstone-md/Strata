//! Hit construction shared by all key detectors (one place for the details layout).

use super::context::Context;
use crate::keys::{AddressSet, Network, PrivateKey, Wif};
use serde_json::{json, Value};
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::Confidence;

/// Details for a recovered private key: both WIF forms, hex and every derived address.
pub fn key_details(key: &PrivateKey, network: Network, compressed: Option<bool>) -> Value {
    json!({
        "hex": key.to_hex(),
        "network": network.name(),
        "compressed": compressed,
        "wif_compressed": Wif::new(*key, network, true).encode(),
        "wif_uncompressed": Wif::new(*key, network, false).encode(),
        "addresses": AddressSet::from_private_key(key, network).to_json(),
    })
}

/// Merge `extra` object fields into `details`.
pub fn with(mut details: Value, extra: Value) -> Value {
    if let (Some(d), Value::Object(e)) = (details.as_object_mut(), extra) {
        d.extend(e);
    }
    details
}

/// Confidence from a base value plus context boosts, capped below certainty.
pub fn scored(base: f32, ctx: &Context) -> Confidence {
    let mut c = base;
    if ctx.strong() {
        c += 0.3;
    } else if ctx.weak() {
        c += 0.1;
    }
    if ctx.alone_on_line() {
        c += 0.05;
    }
    Confidence::new(c.min(0.97))
}

/// Builder entry point used by every detector.
pub fn hit(id: &str, category: HitCategory, base: u64, start: usize, len: usize) -> Hit {
    Hit::new(id, category, base.saturating_add(start as u64), len)
}
