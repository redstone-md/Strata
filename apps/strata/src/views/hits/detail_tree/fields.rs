//! Reading a details object field by field. Every field a mapper reads is marked, so whatever
//! it did not know about still reaches the user through the generic fallback.

use super::generic;
use super::node::TreeNode;
use serde_json::{Map, Value};
use std::cell::RefCell;
use std::collections::BTreeSet;

pub struct Fields<'a> {
    value: &'a Value,
    map: Option<&'a Map<String, Value>>,
    used: RefCell<BTreeSet<&'static str>>,
}

impl<'a> Fields<'a> {
    pub fn new(value: &'a Value) -> Self {
        Self { value, map: value.as_object(), used: RefCell::new(BTreeSet::new()) }
    }

    /// The whole details value.
    pub fn whole(&self) -> &'a Value {
        self.value
    }

    /// The raw value of a key (marked as used), skipping nulls.
    pub fn get(&self, key: &'static str) -> Option<&'a Value> {
        self.used.borrow_mut().insert(key);
        self.map?.get(key).filter(|v| !v.is_null())
    }

    pub fn str(&self, key: &'static str) -> Option<&'a str> {
        self.get(key)?.as_str().filter(|s| !s.is_empty())
    }

    pub fn bool(&self, key: &'static str) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    pub fn u64(&self, key: &'static str) -> Option<u64> {
        self.get(key)?.as_u64()
    }

    pub fn array(&self, key: &'static str) -> &'a [Value] {
        self.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
    }

    /// Mark keys as handled without reading them (shown elsewhere or deliberately hidden).
    pub fn skip(&self, keys: &[&'static str]) {
        self.used.borrow_mut().extend(keys.iter().copied());
    }

    /// A generic "Other" group with every field nobody read, if any.
    pub fn rest(&self) -> Option<TreeNode> {
        let used = self.used.borrow();
        let rows: Vec<_> = self
            .map?
            .iter()
            .filter(|(k, v)| !used.contains(k.as_str()) && !v.is_null())
            .map(|(k, v)| generic::node(k, v))
            .collect();
        (!rows.is_empty()).then(|| TreeNode::group("Other", rows).closed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unread_fields_fall_through_to_other() {
        let v = json!({"network": "mainnet", "mystery": 7, "gone": null});
        let f = Fields::new(&v);
        assert_eq!(f.str("network"), Some("mainnet"));
        let rest = f.rest().expect("one unread field");
        assert_eq!(rest.children.len(), 1);
        assert_eq!(rest.children[0].label, "Mystery");
        f.skip(&["mystery"]);
        assert!(f.rest().is_none());
    }
}
