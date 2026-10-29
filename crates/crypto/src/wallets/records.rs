//! Bitcoin Core wallet.dat record types (data, defined once). Every key in the wallet's
//! Berkeley DB starts with a compact-size length byte and the record type name, e.g.
//! `\x04ckey`. Shared by the wallet.dat parser and the BDB detector.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Unencrypted private key (`key`: pubkey -> DER privkey).
    Key,
    /// Legacy wallet key with metadata (`wkey`).
    WKey,
    /// Encrypted private key (`ckey`: pubkey -> AES ciphertext).
    CKey,
    /// Encrypted master key (`mkey`: id -> salt, iterations, ciphertext).
    MKey,
    /// Address label.
    Name,
    /// Address purpose.
    Purpose,
    /// Pre-generated key pool entry.
    Pool,
    DefaultKey,
    Version,
    MinVersion,
    KeyMeta,
    Tx,
    HdChain,
    BestBlock,
    WalletDescriptor,
    WalletDescriptorKey,
    WalletDescriptorCKey,
    CScript,
}

/// `(record name, kind, strong)`. Strong records only occur in wallets.
pub static RECORD_TYPES: &[(&str, RecordKind, bool)] = &[
    ("key", RecordKind::Key, true),
    ("wkey", RecordKind::WKey, true),
    ("ckey", RecordKind::CKey, true),
    ("mkey", RecordKind::MKey, true),
    ("name", RecordKind::Name, false),
    ("purpose", RecordKind::Purpose, false),
    ("pool", RecordKind::Pool, true),
    ("defaultkey", RecordKind::DefaultKey, true),
    ("version", RecordKind::Version, false),
    ("minversion", RecordKind::MinVersion, true),
    ("keymeta", RecordKind::KeyMeta, true),
    ("tx", RecordKind::Tx, false),
    ("hdchain", RecordKind::HdChain, true),
    ("bestblock", RecordKind::BestBlock, true),
    ("walletdescriptor", RecordKind::WalletDescriptor, true),
    ("walletdescriptorkey", RecordKind::WalletDescriptorKey, true),
    ("walletdescriptorckey", RecordKind::WalletDescriptorCKey, true),
    ("cscript", RecordKind::CScript, true),
];

impl RecordKind {
    pub fn name(self) -> &'static str {
        RECORD_TYPES.iter().find(|r| r.1 == self).map_or("?", |r| r.0)
    }

    /// Identify the record type at the start of a BDB key (`<len><name>...`).
    pub fn from_key(key: &[u8]) -> Option<Self> {
        let (&len, rest) = key.split_first()?;
        let name = rest.get(..usize::from(len))?;
        RECORD_TYPES.iter().find(|r| r.0.as_bytes() == name).map(|r| r.1)
    }
}

/// `len || name` byte patterns for every record type, in table order.
pub fn record_prefixes() -> Vec<Vec<u8>> {
    RECORD_TYPES
        .iter()
        .map(|(name, _, _)| {
            let mut p = vec![name.len() as u8];
            p.extend_from_slice(name.as_bytes());
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_and_lookup() {
        assert!(record_prefixes().contains(&b"\x04ckey".to_vec()));
        assert!(record_prefixes().contains(&b"\x10walletdescriptor".to_vec()));
        assert_eq!(RecordKind::from_key(b"\x04mkey\x01\x00\x00\x00"), Some(RecordKind::MKey));
        assert_eq!(RecordKind::from_key(b"\x03ke"), None);
        assert_eq!(RecordKind::MKey.name(), "mkey");
    }
}
