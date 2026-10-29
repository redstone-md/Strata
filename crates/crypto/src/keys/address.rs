//! Address derivation from public keys: one `AddressSet` per key.

use super::hash::{hash160, tagged_hash};
use super::{base58, Network, PrivateKey};
use bech32::segwit;
use secp256k1::{PublicKey, Scalar, XOnlyPublicKey, SECP256K1};
use serde_json::{json, Value};

/// Every standard single-key address of one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSet {
    network: Network,
    p2pkh_compressed: String,
    p2pkh_uncompressed: String,
    p2sh_p2wpkh: String,
    p2wpkh: String,
    p2tr: String,
}

impl AddressSet {
    pub fn from_private_key(key: &PrivateKey, network: Network) -> Self {
        Self::from_public_key(&key.public_key(), network)
    }

    pub fn from_public_key(pk: &PublicKey, network: Network) -> Self {
        let compressed = pk.serialize();
        let h_c = hash160(&compressed);
        let h_u = hash160(&pk.serialize_uncompressed());
        Self {
            network,
            p2pkh_compressed: p2pkh(&h_c, network),
            p2pkh_uncompressed: p2pkh(&h_u, network),
            p2sh_p2wpkh: p2sh_p2wpkh(&h_c, network),
            p2wpkh: p2wpkh(&h_c, network),
            p2tr: p2tr(pk, network),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn p2pkh_compressed(&self) -> &str {
        &self.p2pkh_compressed
    }

    pub fn p2pkh_uncompressed(&self) -> &str {
        &self.p2pkh_uncompressed
    }

    pub fn p2sh_p2wpkh(&self) -> &str {
        &self.p2sh_p2wpkh
    }

    pub fn p2wpkh(&self) -> &str {
        &self.p2wpkh
    }

    pub fn p2tr(&self) -> &str {
        &self.p2tr
    }

    pub fn all(&self) -> [&str; 5] {
        [
            &self.p2pkh_compressed,
            &self.p2pkh_uncompressed,
            &self.p2sh_p2wpkh,
            &self.p2wpkh,
            &self.p2tr,
        ]
    }

    pub fn to_json(&self) -> Value {
        json!({
            "network": self.network.name(),
            "p2pkh_compressed": self.p2pkh_compressed,
            "p2pkh_uncompressed": self.p2pkh_uncompressed,
            "p2sh_p2wpkh": self.p2sh_p2wpkh,
            "p2wpkh": self.p2wpkh,
            "p2tr": self.p2tr,
        })
    }
}

/// Single-key output script families (BIP44/49/84/86).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    P2pkh,
    P2shP2wpkh,
    P2wpkh,
    P2tr,
}

impl ScriptType {
    pub fn name(self) -> &'static str {
        match self {
            ScriptType::P2pkh => "p2pkh",
            ScriptType::P2shP2wpkh => "p2sh_p2wpkh",
            ScriptType::P2wpkh => "p2wpkh",
            ScriptType::P2tr => "p2tr",
        }
    }

    /// Address of a (compressed) public key under this script type.
    pub fn address(self, pk: &PublicKey, network: Network) -> String {
        match self {
            ScriptType::P2pkh => p2pkh(&hash160(&pk.serialize()), network),
            ScriptType::P2shP2wpkh => p2sh_p2wpkh(&hash160(&pk.serialize()), network),
            ScriptType::P2wpkh => p2wpkh(&hash160(&pk.serialize()), network),
            ScriptType::P2tr => p2tr(pk, network),
        }
    }
}

/// Base58 pay-to-pubkey-hash address.
pub fn p2pkh(pubkey_hash: &[u8; 20], network: Network) -> String {
    base58::encode_check_versioned(&[network.p2pkh_prefix()], pubkey_hash)
}

/// Nested segwit: P2SH wrapping `OP_0 <20-byte hash>`.
pub fn p2sh_p2wpkh(pubkey_hash: &[u8; 20], network: Network) -> String {
    let mut script = [0u8; 22];
    script[0] = 0x00;
    script[1] = 0x14;
    script[2..].copy_from_slice(pubkey_hash);
    base58::encode_check_versioned(&[network.p2sh_prefix()], &hash160(&script))
}

/// Native segwit v0 (bech32).
pub fn p2wpkh(pubkey_hash: &[u8; 20], network: Network) -> String {
    // A 20-byte v0 program is always encodable.
    segwit::encode_v0(network.hrp(), pubkey_hash).unwrap_or_default()
}

/// Taproot key-path output (bech32m) with the BIP341 tweak and no script tree.
pub fn p2tr(pk: &PublicKey, network: Network) -> String {
    let (internal, _) = pk.x_only_public_key();
    taproot_output_key(&internal)
        .and_then(|q| segwit::encode_v1(network.hrp(), &q.serialize()).ok())
        .unwrap_or_default()
}

fn taproot_output_key(internal: &XOnlyPublicKey) -> Option<XOnlyPublicKey> {
    let tweak = tagged_hash("TapTweak", &internal.serialize());
    let scalar = Scalar::from_be_bytes(tweak).ok()?;
    internal.add_tweak(SECP256K1, &scalar).ok().map(|(q, _)| q)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(hex: &str) -> PrivateKey {
        PrivateKey::from_hex(hex.as_bytes()).unwrap()
    }

    #[test]
    fn generator_addresses() {
        let one = key("0000000000000000000000000000000000000000000000000000000000000001");
        let set = AddressSet::from_private_key(&one, Network::Mainnet);
        assert_eq!(set.p2pkh_compressed(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(set.p2pkh_uncompressed(), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        assert_eq!(set.p2wpkh(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(set.p2sh_p2wpkh(), "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN");
        // BIP86 test vector key path: internal key = G for this vector is not used; check format.
        assert!(set.p2tr().starts_with("bc1p") && set.p2tr().len() == 62);
        let t = AddressSet::from_private_key(&one, Network::Testnet);
        assert!(t.p2wpkh().starts_with("tb1q"));
        assert!(t.p2pkh_compressed().starts_with('m') || t.p2pkh_compressed().starts_with('n'));
    }
}
