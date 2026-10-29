//! First-N address derivation along the standard wallet paths.

use super::{format_path, ExtendedKey, HARDENED};
use crate::keys::{Network, ScriptType, Wif};
use serde::Serialize;
use serde_json::Value;

/// One derived receive address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DerivedAddress {
    path: String,
    script: ScriptType,
    address: String,
    /// WIF of the derived private key, when the root was private.
    #[serde(skip_serializing_if = "Option::is_none")]
    wif: Option<String>,
}

impl DerivedAddress {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn script(&self) -> ScriptType {
        self.script
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn wif(&self) -> Option<&str> {
        self.wif.as_deref()
    }
}

/// A path family to walk below a root key: `prefix/<i>` for `i in 0..count`.
#[derive(Debug, Clone, Copy)]
struct Branch {
    prefix: [u32; 4],
    prefix_len: usize,
    script: ScriptType,
    hardened_leaf: bool,
}

impl Branch {
    const fn new(prefix: &[u32], script: ScriptType, hardened_leaf: bool) -> Self {
        let mut p = [0u32; 4];
        let mut i = 0;
        while i < prefix.len() && i < 4 {
            p[i] = prefix[i];
            i += 1;
        }
        Self { prefix: p, prefix_len: if prefix.len() < 4 { prefix.len() } else { 4 }, script, hardened_leaf }
    }

    fn prefix(&self) -> &[u32] {
        &self.prefix[..self.prefix_len]
    }
}

const H: u32 = HARDENED;

/// Derives the first `count` receive addresses of every standard path.
#[derive(Debug, Clone, Copy)]
pub struct DerivationPlan {
    count: u32,
}

impl Default for DerivationPlan {
    fn default() -> Self {
        Self { count: 5 }
    }
}

impl DerivationPlan {
    pub fn new(count: u32) -> Self {
        Self { count: count.min(10_000) }
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    fn branches(root: &ExtendedKey) -> Vec<Branch> {
        let coin = match root.version().network() {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        };
        if root.depth() == 0 {
            let mut v = vec![
                Branch::new(&[44 | H, coin | H, H, 0], ScriptType::P2pkh, false),
                Branch::new(&[49 | H, coin | H, H, 0], ScriptType::P2shP2wpkh, false),
                Branch::new(&[84 | H, coin | H, H, 0], ScriptType::P2wpkh, false),
                Branch::new(&[86 | H, coin | H, H, 0], ScriptType::P2tr, false),
                // Electrum standard wallets and pre-BIP44 software.
                Branch::new(&[0], ScriptType::P2pkh, false),
            ];
            if root.is_private() {
                // Bitcoin Core 0.13+ HD chain.
                v.push(Branch::new(&[H, H], ScriptType::P2pkh, true));
            }
            v
        } else {
            let script = root.version().script().unwrap_or(ScriptType::P2pkh);
            vec![Branch::new(&[0], script, false)]
        }
    }

    /// Addresses for all applicable standard paths below `root`.
    pub fn derive(&self, root: &ExtendedKey) -> Vec<DerivedAddress> {
        let network = root.version().network();
        let mut out = Vec::new();
        for branch in Self::branches(root) {
            let Some(parent) = root.derive_path(branch.prefix()) else { continue };
            for i in 0..self.count {
                let idx = if branch.hardened_leaf { i | H } else { i };
                let Some(child) = parent.derive_child(idx) else { continue };
                let mut path: Vec<u32> = branch.prefix().to_vec();
                path.push(idx);
                out.push(DerivedAddress {
                    path: relative_path(root, &path),
                    script: branch.script,
                    address: branch.script.address(&child.public_key(), network),
                    wif: child.private_key().map(|k| Wif::new(*k, network, true).encode()),
                });
            }
        }
        out
    }

    pub fn derive_json(&self, root: &ExtendedKey) -> Value {
        serde_json::to_value(self.derive(root)).unwrap_or(Value::Null)
    }
}

fn relative_path(root: &ExtendedKey, path: &[u32]) -> String {
    let full = format_path(path);
    if root.depth() == 0 { full } else { full.replacen('m', "<key>", 1) }
}
