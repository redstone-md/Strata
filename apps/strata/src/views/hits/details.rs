//! Reading detector `details` JSON for display. Detectors differ, so this stays tolerant:
//! derived addresses first, then service, then a compact list of scalar fields.

use serde_json::Value;

const ADDRESS_KEYS: [&str; 3] = ["addresses", "derived_addresses", "derived"];
const MAX_SUMMARY: usize = 3;

pub struct HitDetails<'a>(pub &'a Value);

impl HitDetails<'_> {
    pub fn service(&self) -> Option<&str> {
        self.0.get("service").and_then(Value::as_str)
    }

    /// Addresses derived from a key (any of the known keys; arrays or objects of strings).
    pub fn derived_addresses(&self) -> Vec<String> {
        ADDRESS_KEYS
            .iter()
            .filter_map(|k| self.0.get(*k))
            .flat_map(|v| match v {
                Value::Array(items) => items.iter().filter_map(Self::scalar).collect::<Vec<_>>(),
                Value::Object(map) => map.values().filter_map(Self::scalar).collect(),
                other => Self::scalar(other).into_iter().collect(),
            })
            .collect()
    }

    pub fn summary(&self) -> String {
        let derived = self.derived_addresses();
        if !derived.is_empty() {
            let more = derived.len().saturating_sub(MAX_SUMMARY);
            let shown = derived.into_iter().take(MAX_SUMMARY).collect::<Vec<_>>().join(", ");
            return if more > 0 { format!("{shown} +{more}") } else { shown };
        }
        let Value::Object(map) = self.0 else { return Self::scalar(self.0).unwrap_or_default() };
        map.iter()
            .filter_map(|(k, v)| Self::scalar(v).map(|s| format!("{k}: {s}")))
            .take(MAX_SUMMARY)
            .collect::<Vec<_>>()
            .join(" · ")
    }

    fn scalar(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prefers_derived_addresses_then_scalars() {
        let v = json!({"addresses": ["1A", "1B"], "encoding": "wif"});
        assert_eq!(HitDetails(&v).summary(), "1A, 1B");
        let v = json!({"service": "bitcointalk", "encoding": "ascii", "service_kind": null});
        assert_eq!(HitDetails(&v).service(), Some("bitcointalk"));
        let summary = HitDetails(&v).summary();
        assert!(summary.contains("encoding: ascii") && summary.contains("service: bitcointalk"));
        assert!(!summary.contains("service_kind"));
    }
}
