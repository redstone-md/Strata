//! Format-neutral summary of a parsed wallet file.

use crate::keys::{AddressSet, Network, PrivateKey, Wif};
use secp256k1::PublicKey;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use strata_kernel::Damage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletKind {
    BitcoinCore,
    Electrum,
    MultiBitClassic,
    BlockchainInfo,
    Armory,
}

impl WalletKind {
    pub fn name(self) -> &'static str {
        match self {
            WalletKind::BitcoinCore => "bitcoin_core",
            WalletKind::Electrum => "electrum",
            WalletKind::MultiBitClassic => "multibit_classic",
            WalletKind::BlockchainInfo => "blockchain_info",
            WalletKind::Armory => "armory",
        }
    }
}

/// One key found in a wallet: plain secret, encrypted secret or public key only.
#[derive(Debug, Clone)]
pub struct RecoveredKey {
    source: String,
    pubkey: Option<Vec<u8>>,
    secret: Option<Wif>,
    encrypted: Option<Vec<u8>>,
    addresses: Option<AddressSet>,
    deleted: bool,
}

impl RecoveredKey {
    /// A plain private key; addresses are derived from it.
    pub fn plain(source: impl Into<String>, key: PrivateKey, compressed: bool, network: Network) -> Self {
        let pk = key.public_key();
        let pubkey = if compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
        Self {
            source: source.into(),
            pubkey: Some(pubkey),
            secret: Some(Wif::new(key, network, compressed)),
            encrypted: None,
            addresses: Some(AddressSet::from_private_key(&key, network)),
            deleted: false,
        }
    }

    /// Public key only, optionally with the encrypted secret.
    pub fn public(source: impl Into<String>, pubkey: &[u8], encrypted: Option<&[u8]>) -> Self {
        let addresses = PublicKey::from_slice(pubkey).ok().map(|pk| AddressSet::from_public_key(&pk, Network::Mainnet));
        Self {
            source: source.into(),
            pubkey: Some(pubkey.to_vec()),
            secret: None,
            encrypted: encrypted.map(<[u8]>::to_vec),
            addresses,
            deleted: false,
        }
    }

    pub fn mark_deleted(mut self, deleted: bool) -> Self {
        self.deleted = deleted;
        self
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn pubkey(&self) -> Option<&[u8]> {
        self.pubkey.as_deref()
    }

    pub fn secret(&self) -> Option<&Wif> {
        self.secret.as_ref()
    }

    pub fn encrypted(&self) -> Option<&[u8]> {
        self.encrypted.as_deref()
    }

    pub fn addresses(&self) -> Option<&AddressSet> {
        self.addresses.as_ref()
    }

    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// The address that matches the stored public key form (compressed or not).
    pub fn primary_address(&self) -> Option<&str> {
        let set = self.addresses.as_ref()?;
        match self.pubkey.as_ref().map(Vec::len) {
            Some(65) => Some(set.p2pkh_uncompressed()),
            _ => Some(set.p2pkh_compressed()),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "source": self.source,
            "pubkey": self.pubkey.as_ref().map(hex::encode),
            "wif": self.secret.map(|w| w.encode()),
            "secret_hex": self.secret.map(|w| w.key().to_hex()),
            "encrypted": self.encrypted.as_ref().map(hex::encode),
            "addresses": self.addresses.as_ref().map(AddressSet::to_json),
            "deleted": self.deleted,
        })
    }
}

/// Password-cracking input for an encrypted wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrackHash {
    hash: String,
    /// Tool/mode the string is formatted for.
    tool: String,
}

impl CrackHash {
    pub fn new(hash: impl Into<String>, tool: impl Into<String>) -> Self {
        Self { hash: hash.into(), tool: tool.into() }
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }
}

/// Summary of one wallet file.
#[derive(Debug, Clone)]
pub struct WalletReport {
    kind: WalletKind,
    encrypted: Option<bool>,
    keys: Vec<RecoveredKey>,
    addresses: Vec<String>,
    labels: BTreeMap<String, String>,
    crack_hash: Option<CrackHash>,
    metadata: Map<String, Value>,
    damage: Vec<Damage>,
}

impl WalletReport {
    pub fn new(kind: WalletKind) -> Self {
        Self {
            kind,
            encrypted: None,
            keys: Vec::new(),
            addresses: Vec::new(),
            labels: BTreeMap::new(),
            crack_hash: None,
            metadata: Map::new(),
            damage: Vec::new(),
        }
    }

    pub(crate) fn set_encrypted(&mut self, encrypted: bool) {
        self.encrypted = Some(encrypted);
    }

    pub(crate) fn add_key(&mut self, key: RecoveredKey) {
        if let Some(a) = key.primary_address() {
            self.add_address(a);
        }
        self.keys.push(key);
    }

    pub(crate) fn add_address(&mut self, address: &str) {
        if !address.is_empty() && !self.addresses.iter().any(|a| a == address) {
            self.addresses.push(address.to_string());
        }
    }

    pub(crate) fn add_label(&mut self, address: &str, label: &str) {
        self.add_address(address);
        self.labels.insert(address.to_string(), label.to_string());
    }

    pub(crate) fn set_crack_hash(&mut self, hash: CrackHash) {
        if self.crack_hash.is_none() {
            self.crack_hash = Some(hash);
        }
    }

    pub(crate) fn set_meta(&mut self, key: &str, value: Value) {
        self.metadata.insert(key.to_string(), value);
    }

    pub(crate) fn add_damage(&mut self, damage: impl IntoIterator<Item = Damage>) {
        self.damage.extend(damage);
    }

    pub fn kind(&self) -> WalletKind {
        self.kind
    }

    pub fn encrypted(&self) -> Option<bool> {
        self.encrypted
    }

    pub fn keys(&self) -> &[RecoveredKey] {
        &self.keys
    }

    /// Keys whose secret is available in clear.
    pub fn plain_key_count(&self) -> usize {
        self.keys.iter().filter(|k| k.secret.is_some()).count()
    }

    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    pub fn crack_hash(&self) -> Option<&CrackHash> {
        self.crack_hash.as_ref()
    }

    pub fn metadata(&self) -> &Map<String, Value> {
        &self.metadata
    }

    pub fn damage(&self) -> &[Damage] {
        &self.damage
    }

    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.name(),
            "encrypted": self.encrypted,
            "key_count": self.keys.len(),
            "plain_key_count": self.plain_key_count(),
            "keys": self.keys.iter().map(RecoveredKey::to_json).collect::<Vec<_>>(),
            "addresses": self.addresses,
            "labels": self.labels,
            "crack_hash": self.crack_hash,
            "metadata": self.metadata,
            "damage": self.damage,
        })
    }
}
