//! Address validation for text detectors: Base58 P2PKH/P2SH and bech32/bech32m segwit.

use super::{base58, Network};
use bech32::segwit;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    /// Valid segwit encoding with a future witness version.
    WitnessOther,
}

impl AddressKind {
    pub fn name(self) -> &'static str {
        match self {
            AddressKind::P2pkh => "p2pkh",
            AddressKind::P2sh => "p2sh",
            AddressKind::P2wpkh => "p2wpkh",
            AddressKind::P2wsh => "p2wsh",
            AddressKind::P2tr => "p2tr",
            AddressKind::WitnessOther => "witness",
        }
    }
}

/// A checksum-valid address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    text: String,
    kind: AddressKind,
    network: Network,
}

impl Address {
    /// Parse any supported address form; `None` unless the checksum and layout are valid.
    pub fn parse(text: &[u8]) -> Option<Self> {
        match text.first()? {
            b'1' | b'3' | b'm' | b'n' | b'2' => Self::parse_base58(text),
            b'b' | b'B' | b't' | b'T' => Self::parse_segwit(text),
            _ => None,
        }
    }

    fn parse_base58(text: &[u8]) -> Option<Self> {
        if !(26..=35).contains(&text.len()) {
            return None;
        }
        let payload = base58::decode_check(text)?;
        let bytes = payload.as_bytes();
        if bytes.len() != 21 {
            return None;
        }
        let (kind, network) = match bytes[0] {
            0x00 => (AddressKind::P2pkh, Network::Mainnet),
            0x05 => (AddressKind::P2sh, Network::Mainnet),
            0x6f => (AddressKind::P2pkh, Network::Testnet),
            0xc4 => (AddressKind::P2sh, Network::Testnet),
            _ => return None,
        };
        let text = std::str::from_utf8(text).ok()?.to_string();
        Some(Self { text, kind, network })
    }

    fn parse_segwit(text: &[u8]) -> Option<Self> {
        if !(14..=90).contains(&text.len()) {
            return None;
        }
        let s = std::str::from_utf8(text).ok()?;
        let (hrp, version, program) = segwit::decode(s).ok()?;
        let network = if hrp == bech32::hrp::BC {
            Network::Mainnet
        } else if hrp == bech32::hrp::TB {
            Network::Testnet
        } else {
            return None;
        };
        let kind = match (version.to_u8(), program.len()) {
            (0, 20) => AddressKind::P2wpkh,
            (0, 32) => AddressKind::P2wsh,
            (1, 32) => AddressKind::P2tr,
            _ => AddressKind::WitnessOther,
        };
        Some(Self { text: s.to_ascii_lowercase(), kind, network })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    pub fn network(&self) -> Network {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_forms() {
        let a = Address::parse(b"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
        assert_eq!(a.kind(), AddressKind::P2pkh);
        let a = Address::parse(b"3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN").unwrap();
        assert_eq!(a.kind(), AddressKind::P2sh);
        let a = Address::parse(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(a.kind(), AddressKind::P2wpkh);
        let a = Address::parse(b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap();
        assert_eq!(a.as_str(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let a = Address::parse(b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap();
        assert_eq!(a.kind(), AddressKind::P2tr);
    }

    #[test]
    fn rejects_bad_checksums() {
        assert!(Address::parse(b"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMJ").is_none());
        assert!(Address::parse(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_none());
        // bech32 (v0 checksum) used with v1 is invalid under BIP350.
        assert!(Address::parse(b"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx").is_none());
        assert!(Address::parse(b"").is_none());
    }
}
