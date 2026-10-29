use bech32::Hrp;
use serde::Serialize;

/// Bitcoin network parameters that change encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const fn wif_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xef,
        }
    }

    pub const fn p2pkh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
        }
    }

    pub const fn p2sh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet => 0xc4,
        }
    }

    pub fn hrp(self) -> Hrp {
        match self {
            Network::Mainnet => bech32::hrp::BC,
            Network::Testnet => bech32::hrp::TB,
        }
    }

    pub fn from_wif_prefix(prefix: u8) -> Option<Self> {
        [Network::Mainnet, Network::Testnet].into_iter().find(|n| n.wif_prefix() == prefix)
    }

    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}
