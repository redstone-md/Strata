/// Collect every string inside `details` (any nesting) that looks like a mainnet Bitcoin
/// address. Detectors put derived addresses in their details; this keeps the chain context
/// independent of each detector's JSON layout.
pub fn addresses_in(details: &serde_json::Value, out: &mut Vec<String>) {
    match details {
        serde_json::Value::String(s) if looks_like_address(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| addresses_in(v, out)),
        serde_json::Value::Object(map) => map.values().for_each(|v| addresses_in(v, out)),
        _ => {}
    }
}

fn looks_like_address(s: &str) -> bool {
    let base58 = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric() && !b"0OIl".contains(&b));
    match s.as_bytes().first() {
        Some(b'1' | b'3') => (26..=35).contains(&s.len()) && base58(s),
        Some(b'b') => s.starts_with("bc1") && (42..=62).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nested_addresses() {
        let v = serde_json::json!({
            "addresses": {"p2pkh": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "p2wpkh": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
            "label": "x", "list": ["3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "not-an-address"]
        });
        let mut out = Vec::new();
        addresses_in(&v, &mut out);
        out.sort();
        assert_eq!(out.len(), 3);
    }
}
