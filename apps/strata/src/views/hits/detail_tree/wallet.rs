//! Wallet file reports: summary, password-recovery input, keys, labels and damage.

use super::chain::Chain;
use super::fields::Fields;
use super::generic;
use super::key;
use super::node::{Cell, TreeNode};
use crate::format;
use serde_json::Value;

/// Damage entries (`{kind, range: {start, len}?, note}`) as rows.
pub fn damage(entries: &[Value]) -> Option<TreeNode> {
    if entries.is_empty() {
        return None;
    }
    let rows = entries
        .iter()
        .map(|d| {
            let kind = d.get("kind").and_then(Value::as_str).unwrap_or("Damage");
            let note = d.get("note").and_then(Value::as_str).unwrap_or("");
            let range = d.get("range").filter(|r| !r.is_null()).and_then(|r| {
                let start = r.get("start")?.as_u64()?;
                Some(format!("{} ({})", format::hex_offset(start), format::bytes(r.get("len")?.as_u64()?)))
            });
            let row = TreeNode::text(generic::humanize(kind), note);
            match range {
                Some(r) => TreeNode::group(generic::humanize(kind), vec![TreeNode::data("Range", r), TreeNode::text("Note", note)])
                    .summary(Cell::Text(note.to_string()))
                    .closed(),
                None => row,
            }
        })
        .collect();
    Some(TreeNode::group("Damage", rows).summary(Cell::Badge(entries.len().to_string(), true)))
}

fn recovered_key(i: usize, k: &Value, chain: &Chain) -> TreeNode {
    let s = |key: &str| k.get(key).and_then(Value::as_str);
    let mut rows: Vec<TreeNode> = [
        s("wif").map(|w| TreeNode::data("WIF", w)),
        s("secret_hex").map(|h| TreeNode::data("Secret hex", h)),
        s("encrypted").map(|e| TreeNode::data("Encrypted key", e)),
        s("pubkey").map(|p| TreeNode::data("Public key", p)),
        s("source").map(|src| TreeNode::text("Found in", src)),
        k.get("deleted").and_then(Value::as_bool).filter(|d| *d).map(|_| TreeNode::row("State", Cell::Badge("deleted".into(), false))),
    ]
    .into_iter()
    .flatten()
    .collect();
    rows.extend(k.get("addresses").and_then(|set| key::addresses(set, chain, |_| Vec::new())));
    let summary = match (s("wif"), s("encrypted")) {
        (Some(_), _) => Cell::Text("readable".into()),
        (None, Some(_)) => Cell::Badge("encrypted".into(), true),
        _ => Cell::Quiet("public only".into()),
    };
    TreeNode::group(format!("Key {}", i + 1), rows).summary(summary).closed()
}

pub fn build(f: &Fields, chain: &Chain) -> Vec<TreeNode> {
    let encrypted = f.bool("encrypted");
    let (total, plain) = (f.u64("key_count").unwrap_or(0), f.u64("plain_key_count").unwrap_or(0));
    let summary: Vec<_> = [
        f.str("kind").map(|k| TreeNode::text("Wallet", k)),
        encrypted.map(|e| if e { TreeNode::row("Encrypted", Cell::Badge("encrypted".into(), true)) } else { TreeNode::yes_no("Encrypted", false) }),
        Some(TreeNode::text("Keys", format!("{total}: {plain} readable, {} encrypted", total.saturating_sub(plain)))),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut out = vec![TreeNode::group("Summary", summary)];
    if let Some(hash) = f.get("crack_hash") {
        let text = hash.get("hash").and_then(Value::as_str).unwrap_or("");
        let mut rows = vec![TreeNode::data("Hash", text)];
        rows.extend(hash.get("tool").and_then(Value::as_str).map(|t| TreeNode::text("Format", t)));
        if text.starts_with("$bitcoin$") {
            rows.push(TreeNode::note("hashcat mode 11300"));
        }
        out.push(TreeNode::group("Password recovery", rows));
    }
    let keys = f.array("keys");
    if !keys.is_empty() {
        out.push(TreeNode::group("Keys", keys.iter().enumerate().map(|(i, k)| recovered_key(i, k, chain)).collect()).summary(Cell::Quiet(keys.len().to_string())));
    }
    let addresses: Vec<&str> = f.array("addresses").iter().filter_map(Value::as_str).collect();
    if !addresses.is_empty() {
        let tally = chain.tally(addresses.iter().copied());
        let rows = addresses.iter().enumerate().map(|(i, a)| chain.address((i + 1).to_string(), a, Vec::new())).collect();
        out.push(TreeNode::group("Addresses", rows).summary(tally).closed());
    }
    if let Some(labels) = f.get("labels").and_then(Value::as_object).filter(|m| !m.is_empty()) {
        let rows = labels.iter().map(|(addr, label)| TreeNode::data(label.as_str().unwrap_or(""), addr.clone())).collect();
        out.push(TreeNode::group("Labels", rows).closed());
    }
    if let Some(meta) = f.get("metadata").filter(|m| m.as_object().is_some_and(|m| !m.is_empty())) {
        out.push(TreeNode::group("Metadata", generic::tree(meta)).closed());
    }
    out.extend(damage(f.array("damage")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::hits::detail_tree::node::find;
    use serde_json::json;

    #[test]
    fn maps_an_encrypted_wallet() {
        let d = json!({
            "kind": "Bitcoin Core", "encrypted": true, "key_count": 2, "plain_key_count": 0,
            "keys": [{"encrypted": "aa", "pubkey": "02bb", "source": "ckey", "deleted": false, "addresses": null}],
            "addresses": ["1A"], "labels": {"1A": "savings"},
            "crack_hash": {"hash": "$bitcoin$64$abc", "tool": "hashcat"},
            "metadata": {}, "damage": [{"kind": "Truncated", "range": {"start": 4096, "len": 512}, "note": "page cut"}]
        });
        let t = build(&Fields::new(&d), &Chain::default());
        assert_eq!(find(&t, "Encrypted").and_then(|n| n.cell.clone()), Some(Cell::Badge("encrypted".into(), true)));
        let recovery = find(&t, "Password recovery").expect("crack hash");
        assert!(recovery.children.iter().any(|n| n.note));
        assert_eq!(find(&t, "Key 1").and_then(|n| n.cell.clone()), Some(Cell::Badge("encrypted".into(), true)));
        assert!(find(&t, "savings").is_some());
        assert!(find(&t, "Range").is_some());
        assert!(find(&t, "Metadata").is_none());
    }
}
