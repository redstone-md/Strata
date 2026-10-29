//! Fallback for anything without a dedicated mapping: objects become groups, arrays indexed
//! groups, scalars rows. Still a tree in the same style, never raw text.

use super::node::{Cell, TreeNode};
use serde_json::Value;

/// `p2sh_p2wpkh` → `P2sh p2wpkh`, `keyCount` → `Key count`.
pub fn humanize(key: &str) -> String {
    let mut out = String::new();
    for (i, ch) in key.chars().enumerate() {
        match ch {
            '_' | '-' => out.push(' '),
            c if c.is_uppercase() && i > 0 => {
                out.push(' ');
                out.extend(c.to_lowercase());
            }
            c if i == 0 => out.extend(c.to_uppercase()),
            c => out.push(c),
        }
    }
    out
}

/// Strings that are data (keys, hashes, addresses, paths) rather than prose.
pub fn looks_like_data(s: &str) -> bool {
    let compact = !s.contains(' ');
    let hexish = s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit());
    let pathish = s.contains('\\') || s.contains('/');
    hexish || pathish || (compact && s.len() >= 24)
}

/// A scalar as a row cell.
pub fn scalar(v: &Value) -> Option<Cell> {
    match v {
        Value::String(s) if looks_like_data(s) => Some(Cell::Data(s.clone())),
        Value::String(s) => Some(Cell::Text(s.clone())),
        Value::Number(n) => Some(Cell::Text(n.to_string())),
        Value::Bool(b) => Some(Cell::Text(if *b { "yes" } else { "no" }.into())),
        _ => None,
    }
}

pub fn node(key: &str, v: &Value) -> TreeNode {
    let label = humanize(key);
    match v {
        Value::Object(map) => {
            TreeNode::group(label, map.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| node(k, v)).collect()).closed()
        }
        Value::Array(items) if items.is_empty() => TreeNode::quiet(label, "none"),
        Value::Array(items) => TreeNode::group(
            label,
            items.iter().enumerate().map(|(i, v)| node(&(i + 1).to_string(), v)).collect(),
        )
        .summary(Cell::Quiet(items.len().to_string()))
        .closed(),
        other => match scalar(other) {
            Some(Cell::Data(s)) => TreeNode::data(label, s),
            Some(cell) => TreeNode::row(label, cell),
            None => TreeNode::quiet(label, "none"),
        },
    }
}

/// The whole value as a forest (top-level keys become rows/groups).
pub fn tree(v: &Value) -> Vec<TreeNode> {
    match v {
        Value::Object(map) => map.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| node(k, v)).collect(),
        Value::Null => Vec::new(),
        other => vec![node("value", other)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_json_to_a_tree() {
        assert_eq!(humanize("plain_key_count"), "Plain key count");
        assert_eq!(humanize("typeId"), "Type id");
        let t = tree(&json!({"a": {"b": true}, "list": [1, 2], "hash": "0c28fca386c7a227600b2fe50b7cae11"}));
        assert_eq!(t.len(), 3);
        assert!(t[0].is_group() && t[0].children[0].cell == Some(Cell::Text("yes".into())));
        assert_eq!(t[1].children.len(), 2);
        assert!(matches!(t[2].cell, Some(Cell::Data(_))) && t[2].copy.is_some());
    }
}
