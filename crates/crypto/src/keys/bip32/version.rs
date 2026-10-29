//! SLIP-132 extended key version bytes (data, defined once).

use crate::keys::{Network, ScriptType};

/// What an extended key's 4-byte version says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyVersion {
    bytes: [u8; 4],
    prefix: &'static str,
    network: Network,
    private: bool,
    /// Single-key script type; `None` for multisig (`Y`/`Z`/`U`/`V` prefixes).
    script: Option<ScriptType>,
}

macro_rules! v {
    ($b:expr, $p:literal, $n:ident, $priv:literal, $s:expr) => {
        KeyVersion { bytes: $b, prefix: $p, network: Network::$n, private: $priv, script: $s }
    };
}

use ScriptType::{P2pkh, P2shP2wpkh, P2wpkh};

const VERSIONS: &[KeyVersion] = &[
    v!([0x04, 0x88, 0xad, 0xe4], "xprv", Mainnet, true, Some(P2pkh)),
    v!([0x04, 0x88, 0xb2, 0x1e], "xpub", Mainnet, false, Some(P2pkh)),
    v!([0x04, 0x9d, 0x78, 0x78], "yprv", Mainnet, true, Some(P2shP2wpkh)),
    v!([0x04, 0x9d, 0x7c, 0xb2], "ypub", Mainnet, false, Some(P2shP2wpkh)),
    v!([0x04, 0xb2, 0x43, 0x0c], "zprv", Mainnet, true, Some(P2wpkh)),
    v!([0x04, 0xb2, 0x47, 0x46], "zpub", Mainnet, false, Some(P2wpkh)),
    v!([0x02, 0x95, 0xb0, 0x05], "Yprv", Mainnet, true, None),
    v!([0x02, 0x95, 0xb4, 0x3f], "Ypub", Mainnet, false, None),
    v!([0x02, 0xaa, 0x7a, 0x99], "Zprv", Mainnet, true, None),
    v!([0x02, 0xaa, 0x7e, 0xd3], "Zpub", Mainnet, false, None),
    v!([0x04, 0x35, 0x83, 0x94], "tprv", Testnet, true, Some(P2pkh)),
    v!([0x04, 0x35, 0x87, 0xcf], "tpub", Testnet, false, Some(P2pkh)),
    v!([0x04, 0x4a, 0x4e, 0x28], "uprv", Testnet, true, Some(P2shP2wpkh)),
    v!([0x04, 0x4a, 0x52, 0x62], "upub", Testnet, false, Some(P2shP2wpkh)),
    v!([0x04, 0x5f, 0x18, 0xbc], "vprv", Testnet, true, Some(P2wpkh)),
    v!([0x04, 0x5f, 0x1c, 0xf6], "vpub", Testnet, false, Some(P2wpkh)),
    v!([0x02, 0x42, 0x85, 0xb5], "Uprv", Testnet, true, None),
    v!([0x02, 0x42, 0x89, 0xef], "Upub", Testnet, false, None),
    v!([0x02, 0x57, 0x50, 0x48], "Vprv", Testnet, true, None),
    v!([0x02, 0x57, 0x54, 0x83], "Vpub", Testnet, false, None),
];

impl KeyVersion {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        VERSIONS.iter().copied().find(|v| v.bytes == bytes)
    }

    /// Every 4-character text prefix (`xprv`, `zpub`...), for detector prefilters.
    pub fn all_prefixes() -> impl Iterator<Item = &'static str> {
        VERSIONS.iter().map(|v| v.prefix)
    }

    pub fn find(network: Network, private: bool, script: ScriptType) -> Option<Self> {
        VERSIONS
            .iter()
            .copied()
            .find(|v| v.network == network && v.private == private && v.script == Some(script))
    }

    pub fn bytes(&self) -> [u8; 4] {
        self.bytes
    }

    pub fn prefix(&self) -> &'static str {
        self.prefix
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn is_private(&self) -> bool {
        self.private
    }

    pub fn script(&self) -> Option<ScriptType> {
        self.script
    }

    /// The public counterpart of a private version.
    pub fn to_public(&self) -> Self {
        if !self.private {
            return *self;
        }
        VERSIONS
            .iter()
            .copied()
            .find(|v| !v.private && v.network == self.network && v.prefix[..1] == self.prefix[..1])
            .unwrap_or(*self)
    }
}
