//! File signatures, renamed files and carved files: what the bytes really are, how much of
//! the structure holds, what is inside and what is damaged.

use super::fields::Fields;
use super::generic;
use super::node::{Cell, TreeNode};
use super::wallet;
use crate::format;
use serde_json::Value;

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// A `TypeVerdict` (classifier output) as groups.
fn verdict(v: &Value) -> Vec<TreeNode> {
    let mut kind: Vec<TreeNode> = [
        s(v, "type_name").map(|t| TreeNode::text("Detected type", t)),
        s(v, "category").map(|c| TreeNode::text("Category", c)),
        s(v, "method").map(|m| TreeNode::text("Identified by", generic::humanize(m))),
        v.get("confidence").and_then(Value::as_f64).map(|c| TreeNode::text("Confidence", format::percent(c as f32))),
        v.get("valid_fraction").and_then(Value::as_f64).map(|f| TreeNode::row("Structure valid", Cell::Bar(f as f32))),
        v.get("declared_len").and_then(Value::as_u64).map(|l| TreeNode::text("Declared size", format::bytes(l))),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(m) = v.get("extension_mismatch").filter(|m| !m.is_null()) {
        let declared = s(m, "declared").unwrap_or("none");
        let actual = s(m, "actual").unwrap_or("unknown");
        kind.push(TreeNode::text("Extension", format!(".{declared} but is {actual}")));
        if m.get("suspicious").and_then(Value::as_bool) == Some(true) {
            kind.push(TreeNode::row("Renamed", Cell::Badge("suspicious".into(), true)));
        }
        kind.extend(s(m, "reason").map(TreeNode::note));
    }
    let mut out = vec![TreeNode::group("File type", kind)];
    let inner = v.get("inner").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    if !inner.is_empty() {
        let rows = inner
            .iter()
            .map(|i| {
                let name = s(i, "name").unwrap_or("");
                let size = i.get("size").and_then(Value::as_u64).map(format::bytes);
                let kind = s(i, "kind").map(generic::humanize).unwrap_or_default();
                TreeNode::row(kind, Cell::Data(match size {
                    Some(sz) => format!("{name}  {sz}"),
                    None => name.to_string(),
                }))
            })
            .collect();
        out.push(TreeNode::group("Contents", rows).summary(Cell::Quiet(inner.len().to_string())).closed());
    }
    let notes: Vec<_> = v.get("notes").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(TreeNode::note).collect();
    if !notes.is_empty() {
        out.push(TreeNode::group("Notes", notes));
    }
    out.extend(wallet::damage(v.get("damage").and_then(Value::as_array).map_or(&[][..], Vec::as_slice)));
    out
}

pub fn build(f: &Fields) -> Vec<TreeNode> {
    f.skip(&["profile"]);
    // Carved file: `{range, length, verdict, damage}`.
    if let Some(v) = f.get("verdict") {
        let mut out = verdict(v);
        if let Some(r) = f.get("range") {
            let start = r.get("start").and_then(Value::as_u64).unwrap_or(0);
            let rows = vec![
                TreeNode::data("Starts at", format::hex_offset(start)),
                TreeNode::text("Length", format::bytes(f.u64("length").unwrap_or(0))),
            ];
            out.insert(1, TreeNode::group("Carved from free space", rows));
        }
        out.extend(wallet::damage(f.array("damage")));
        return out;
    }
    // Signature at a sector: `{type_id, category, declared_len, validated}`.
    if let Some(type_id) = f.str("type_id") {
        let rows = [
            Some(TreeNode::text("Signature of", type_id)),
            f.str("category").map(|c| TreeNode::text("Category", c)),
            f.u64("declared_len").map(|l| TreeNode::text("Declared size", format::bytes(l))),
            f.bool("validated").map(|v| TreeNode::text("Structure", if v { "checked and valid" } else { "not checked" })),
        ]
        .into_iter()
        .flatten()
        .collect();
        return vec![TreeNode::group("File type", rows)];
    }
    // Classifier verdict stored as the details themselves.
    f.skip(&["type_name", "file_type", "category", "method", "confidence", "valid_fraction", "declared_len", "extension_mismatch", "inner", "notes", "damage"]);
    verdict(f.whole())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::hits::detail_tree::node::find;
    use serde_json::json;

    #[test]
    fn maps_a_renamed_file() {
        let d = json!({
            "type_name": "ZIP archive", "category": "Archive", "method": "Structure", "confidence": 0.9,
            "valid_fraction": 0.75, "extension_mismatch": {"declared": "jpg", "actual": "Zip", "expected": ["zip"], "suspicious": true, "reason": "archive named as a picture"},
            "inner": [{"kind": "ArchiveMember", "name": "wallet.dat", "size": 65536}], "notes": [], "damage": [], "profile": {}
        });
        let t = build(&Fields::new(&d));
        assert_eq!(find(&t, "Structure valid").and_then(|n| n.cell.clone()), Some(Cell::Bar(0.75)));
        assert_eq!(find(&t, "Extension").and_then(|n| n.cell.clone()), Some(Cell::Text(".jpg but is Zip".into())));
        assert_eq!(find(&t, "Contents").map(|n| n.children.len()), Some(1));
    }
}
