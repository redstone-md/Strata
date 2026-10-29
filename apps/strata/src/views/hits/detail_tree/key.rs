//! Private keys (WIF, hex, DER, minikey): what the key is, the secret in both forms, and every
//! address it controls with its on-chain state.

use super::chain::Chain;
use super::fields::Fields;
use super::node::{TreeNode, non_empty};
use serde_json::Value;

/// Address kinds in the order a recovery specialist checks them.
pub const SCRIPTS: [(&str, &str); 5] = [
    ("p2pkh_compressed", "P2PKH compressed"),
    ("p2pkh_uncompressed", "P2PKH uncompressed"),
    ("p2sh_p2wpkh", "P2SH-P2WPKH"),
    ("p2wpkh", "P2WPKH"),
    ("p2tr", "P2TR"),
];

/// The address set a key derives (`addresses` object of detectors and wallet keys).
pub fn addresses(set: &Value, chain: &Chain, extra_for: impl Fn(&str) -> Vec<TreeNode>) -> Option<TreeNode> {
    let present: Vec<(&str, &str)> =
        SCRIPTS.iter().filter_map(|(key, label)| Some((*label, set.get(*key)?.as_str()?))).collect();
    if present.is_empty() {
        return None;
    }
    let tally = chain.tally(present.iter().map(|(_, a)| *a));
    let rows = present.iter().map(|(label, a)| chain.address(*label, a, extra_for(a))).collect();
    Some(TreeNode::group("Addresses", rows).summary(tally))
}

pub fn build(label: &str, f: &Fields, chain: &Chain) -> Vec<TreeNode> {
    let compressed = f.bool("compressed");
    let key = TreeNode::group(
        "Key",
        [
            Some(TreeNode::text("Format", label)),
            f.str("network").map(|n| TreeNode::text("Network", n)),
            compressed.map(|c| TreeNode::yes_no("Compressed", c)),
        ]
        .into_iter()
        .flatten()
        .collect(),
    );
    let (main, other) = if compressed == Some(false) {
        (("WIF", "wif_uncompressed"), ("WIF compressed", "wif_compressed"))
    } else {
        (("WIF", "wif_compressed"), ("WIF uncompressed", "wif_uncompressed"))
    };
    let secret = TreeNode::group(
        "Secret",
        [main, other, ("Hex", "hex")]
            .into_iter()
            .filter_map(|(label, key)| Some(TreeNode::data(label, f.str(key)?)))
            .collect(),
    );
    let addresses = f.get("addresses").and_then(|set| addresses(set, chain, |_| Vec::new()));
    let mut out = non_empty(vec![key, secret]);
    out.extend(addresses);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::hits::detail_tree::node::{Cell, find};
    use serde_json::json;

    #[test]
    fn maps_a_wif_hit() {
        let d = json!({
            "addresses": {"network": "mainnet", "p2pkh_compressed": "1LoV", "p2wpkh": "bc1qmy"},
            "compressed": true, "network": "mainnet", "hex": "0c28",
            "wif_compressed": "KwdM", "wif_uncompressed": "5Hue"
        });
        let t = build("WIF compressed mainnet", &Fields::new(&d), &Chain::default());
        assert_eq!(find(&t, "WIF").and_then(|n| n.copy.clone()).as_deref(), Some("KwdM"));
        assert_eq!(find(&t, "WIF uncompressed").and_then(|n| n.cell.clone()), Some(Cell::Data("5Hue".into())));
        let addrs = find(&t, "Addresses").expect("addresses group");
        assert_eq!(addrs.children.len(), 2);
        assert_eq!(addrs.children[0].label, "P2PKH compressed");
    }
}
