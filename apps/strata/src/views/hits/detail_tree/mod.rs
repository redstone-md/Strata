//! A finding's details as a typed tree: one mapper per finding type, a Location group for
//! every finding, a generic fallback for unknown fields and an optional Raw group.

mod chain;
mod fields;
mod file;
mod generic;
mod key;
mod node;
mod seed;
mod view;
mod wallet;

pub use chain::Chain;
pub use view::{DetailTree, TreeState};

use crate::format;
use fields::Fields;
use node::{Cell, TreeNode};
use strata_workbench::{HitCategory, StoredHit};

/// Rows for services, identities, addresses and markers: whatever the detector recorded.
fn account(f: &Fields, value: &str, category: HitCategory, chain: &Chain) -> Vec<TreeNode> {
    let rows: Vec<_> = [
        f.str("service").map(|s| TreeNode::text("Service", s)),
        f.str("service_kind").map(|k| TreeNode::text("Kind", k)),
        f.str("kind").map(|k| TreeNode::text("Address type", k.to_uppercase())),
        f.str("strength").map(|s| TreeNode::text("Marker strength", s.to_lowercase())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut out = vec![];
    if !rows.is_empty() {
        out.push(TreeNode::group(if category == HitCategory::Address { "Address" } else { "Account" }, rows));
    }
    if category == HitCategory::Address {
        out.push(TreeNode::group("On chain", vec![TreeNode::row("Balance", chain.cell(value))]));
    }
    out
}

/// How the text was found: encoding and the surrounding context.
fn context(f: &Fields) -> Option<TreeNode> {
    let mut rows: Vec<TreeNode> = f.str("encoding").map(|e| TreeNode::text("Encoding", e)).into_iter().collect();
    if let Some(c) = f.get("context") {
        let flag = |k: &str| c.get(k).and_then(serde_json::Value::as_bool);
        rows.extend(flag("alone_on_line").map(|v| TreeNode::yes_no("Alone on its line", v)));
        rows.extend(flag("strong").map(|v| TreeNode::yes_no("Wallet words nearby", v)));
        let words: Vec<&str> =
            c.get("keywords").and_then(serde_json::Value::as_array).into_iter().flatten().filter_map(|w| w.as_str()).collect();
        if !words.is_empty() {
            rows.push(TreeNode::text("Keywords", words.join(", ")));
        }
    }
    (!rows.is_empty()).then(|| TreeNode::group("Context", rows).closed())
}

/// Where the finding is: disk, volume, file, offsets, and the triage verdict.
fn location(hit: &StoredHit, disk: &str, f: &Fields) -> TreeNode {
    let mut rows = vec![TreeNode::text("Disk", disk)];
    rows.extend(hit.volume.map(|v| TreeNode::text("Volume", v.to_string())));
    match &hit.file_path {
        Some(path) => {
            let mut file = TreeNode::data("File", path.clone());
            if let Some(state) = hit.file_state.as_deref().filter(|s| matches!(*s, "Deleted" | "Orphan")) {
                file = TreeNode::group("File", vec![TreeNode::data("Path", path.clone())])
                    .summary(Cell::Badge(state.to_lowercase(), false));
            }
            rows.push(file);
        }
        None => rows.push(TreeNode::quiet("File", "not inside a known file")),
    }
    rows.extend(hit.file_offset.map(|o| TreeNode::data("Offset in file", format::hex_offset(o))));
    rows.push(TreeNode::data("Disk offset", format::hex_offset(hit.hit.offset)));
    rows.push(TreeNode::text("Length", format::count(hit.hit.len as u64, "byte", "bytes")));
    rows.push(TreeNode::text("Confidence", format::percent(hit.hit.confidence.get())));
    if f.str("triage").is_some() {
        rows.push(TreeNode::note("Inside a system file, likely a false positive"));
    }
    TreeNode::group("Location", rows)
}

/// The full tree for one finding.
pub fn build(hit: &StoredHit, disk: &str, chain: &Chain, show_raw: bool) -> Vec<TreeNode> {
    let details = &hit.hit.details;
    let f = Fields::new(details);
    let mut out = match hit.hit.category {
        HitCategory::PrivateKey => key::build(&hit.hit.label, &f, chain),
        HitCategory::Mnemonic => seed::mnemonic(&f, chain),
        HitCategory::ExtendedKey => seed::extended(&f, chain),
        HitCategory::Wallet => wallet::build(&f, chain),
        HitCategory::FileSignature => file::build(&f),
        category => account(&f, &hit.hit.value, category, chain),
    };
    out.extend(context(&f));
    out.push(location(hit, disk, &f));
    out.extend(f.rest());
    if show_raw {
        let raw = serde_json::to_string_pretty(details).unwrap_or_default();
        out.push(TreeNode::group("Raw", vec![TreeNode::row("", Cell::Data(raw))]).closed());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::find;
    use serde_json::json;

    fn stored(category: HitCategory, details: serde_json::Value) -> StoredHit {
        let hit = json!({"detector": "test", "category": category, "offset": 0x3052e1, "len": 51,
            "confidence": 0.9, "label": "test", "value": "1A1z", "details": details});
        StoredHit {
            id: 1,
            evidence: serde_json::from_value(json!(1)).expect("evidence id"),
            hit: serde_json::from_value(hit).expect("hit"),
            volume: Some(0),
            file_path: Some(r"Users\a\wallet.dat".into()),
            file_state: Some("Deleted".into()),
            file_offset: Some(16),
        }
    }

    #[test]
    fn every_finding_gets_location_and_unknown_fields() {
        let hit = stored(HitCategory::Address, json!({"kind": "p2pkh", "triage": "inside system file", "odd": 1, "encoding": "ascii"}));
        let t = build(&hit, "laptop.img", &Chain::default(), false);
        assert!(find(&t, "Location").is_some_and(|l| l.children.iter().any(|n| n.note)));
        assert_eq!(find(&t, "File").and_then(|n| n.cell.clone()), Some(Cell::Badge("deleted".into(), false)));
        assert!(find(&t, "Other").is_some_and(|o| o.children[0].label == "Odd"));
        assert!(find(&t, "Raw").is_none());
        assert!(find(&build(&hit, "x", &Chain::default(), true), "Raw").is_some());
    }
}
