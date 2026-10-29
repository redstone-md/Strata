//! Seed phrases and extended keys: what the seed or key is, then its derivation paths, each
//! opening to the derived addresses with their on-chain state.

use super::chain::Chain;
use super::fields::Fields;
use super::node::{Cell, TreeNode};
use serde_json::Value;

/// Derivation scheme of a path, by its leading components.
pub fn scheme(path: &str) -> &'static str {
    let rest = path.trim_start_matches("m/").trim_start_matches("<key>/");
    match rest.split('/').next().unwrap_or("") {
        "44'" => "BIP44, legacy",
        "49'" => "BIP49, nested SegWit",
        "84'" => "BIP84, native SegWit",
        "86'" => "BIP86, Taproot",
        "0'" => "Bitcoin Core",
        "0" | "1" => "Electrum and plain BIP32",
        _ => "Other paths",
    }
}

/// The tail of a path below its scheme's account (`m/84'/0'/0'/0/1` → `0/1`).
fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 3 { parts[parts.len() - 2..].join("/") } else { path.to_string() }
}

/// `derived` entries (`{path, address, script?, wif?}`) grouped by scheme, in first-seen order.
fn derivation(derived: &[Value], chain: &Chain) -> Option<TreeNode> {
    let mut groups: Vec<(&'static str, Vec<&Value>)> = Vec::new();
    for d in derived {
        let Some(path) = d.get("path").and_then(Value::as_str) else { continue };
        let name = scheme(path);
        match groups.iter_mut().find(|(n, _)| *n == name) {
            Some((_, list)) => list.push(d),
            None => groups.push((name, vec![d])),
        }
    }
    if groups.is_empty() {
        return None;
    }
    let schemes = groups
        .into_iter()
        .map(|(name, entries)| {
            let addresses: Vec<&str> = entries.iter().filter_map(|d| d.get("address")?.as_str()).collect();
            let tally = chain.tally(addresses.iter().copied());
            let any_used = addresses.iter().any(|a| chain.used(a));
            let rows = entries
                .iter()
                .filter_map(|d| {
                    let (path, address) = (d.get("path")?.as_str()?, d.get("address")?.as_str()?);
                    let wif = d.get("wif").and_then(Value::as_str).map(|w| TreeNode::data("WIF", w));
                    Some(chain.address(short_path(path), address, wif.into_iter().collect()))
                })
                .collect();
            TreeNode::group(name, rows).summary(tally).open_if(any_used)
        })
        .collect();
    Some(TreeNode::group("Derivation paths", schemes))
}

pub fn mnemonic(f: &Fields, chain: &Chain) -> Vec<TreeNode> {
    let kind = f.str("type");
    let electrum = kind == Some("electrum");
    let rows: Vec<_> = [
        Some(TreeNode::text("Type", if electrum { "Electrum seed" } else { "BIP39" })),
        f.str("seed_type").map(|s| TreeNode::text("Electrum version", s)),
        f.str("language").map(|l| TreeNode::text("Language", l)),
        f.u64("words").map(|w| TreeNode::text("Words", w.to_string())),
        (!electrum && kind.is_some()).then(|| TreeNode::text("Checksum", "valid")),
        f.bool("exact_run").map(|e| TreeNode::text("Layout", if e { "one unbroken run of words" } else { "words with gaps" })),
        f.str("master_xprv").map(|x| TreeNode::data("Master key", x)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut out = vec![TreeNode::group("Seed", rows)];
    out.extend(derivation(f.array("derived"), chain));
    out
}

pub fn extended(f: &Fields, chain: &Chain) -> Vec<TreeNode> {
    let private = f.bool("private");
    let key_text = f.str("xprv").or(f.str("xpub")).or(f.str("key"));
    let rows: Vec<_> = [
        f.str("prefix").map(|p| TreeNode::text("Prefix", p)),
        f.str("network").map(|n| TreeNode::text("Network", n)),
        private.map(|p| TreeNode::text("Contains", if p { "private key" } else { "public key only" })),
        f.u64("depth").map(|d| TreeNode::text("Depth", d.to_string())),
        f.u64("child_number").map(|c| TreeNode::text("Child number", c.to_string())),
        f.str("fingerprint").map(|x| TreeNode::data("Fingerprint", x)),
        f.str("parent_fingerprint").map(|x| TreeNode::data("Parent fingerprint", x)),
        key_text.map(|k| TreeNode::data("Key", k)),
        f.str("key_wif").map(|w| TreeNode::data("WIF", w)),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut out = vec![TreeNode::group("Key", rows).summary(Cell::Quiet(if private == Some(true) { "private" } else { "public" }.into()))];
    out.extend(derivation(f.array("derived"), chain));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::hits::detail_tree::node::find;
    use serde_json::json;

    #[test]
    fn groups_derived_addresses_by_scheme() {
        assert_eq!(scheme("m/84'/0'/0'/0/1"), "BIP84, native SegWit");
        assert_eq!(scheme("m/0'/0'/2'"), "Bitcoin Core");
        assert_eq!(scheme("<key>/0/1"), "Electrum and plain BIP32");
        assert_eq!(short_path("m/84'/0'/0'/0/1"), "0/1");
        assert_eq!(short_path("m/0/2"), "m/0/2");
        let d = json!({"type": "bip39", "language": "english", "words": 12, "derived": [
            {"path": "m/44'/0'/0'/0/0", "address": "1A", "wif": "L1"},
            {"path": "m/44'/0'/0'/0/1", "address": "1B"},
            {"path": "m/84'/0'/0'/0/0", "address": "bc1q"}
        ]});
        let t = mnemonic(&Fields::new(&d), &Chain::default());
        let paths = find(&t, "Derivation paths").expect("paths");
        assert_eq!(paths.children.len(), 2);
        assert_eq!(paths.children[0].children.len(), 2);
        assert!(find(&t, "WIF").is_some());
        assert_eq!(find(&t, "Checksum").and_then(|n| n.cell.clone()), Some(Cell::Text("valid".into())));
    }
}
