//! BIP32 extended keys: parse, validate, encode, derive children.

use super::KeyVersion;
use crate::keys::hash::{hash160, hmac_sha512, hmac_sha512_parts};
use crate::keys::{base58, PrivateKey};
use secp256k1::{PublicKey, Scalar, SECP256K1};

/// Index bit for hardened derivation.
pub const HARDENED: u32 = 0x8000_0000;
/// Serialized payload length (version..key).
const PAYLOAD_LEN: usize = 78;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Material {
    Private(PrivateKey),
    Public(PublicKey),
}

/// An `xprv`/`xpub`-family key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedKey {
    version: KeyVersion,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    material: Material,
}

impl ExtendedKey {
    /// BIP32 master key from a seed (`HMAC-SHA512("Bitcoin seed", seed)`).
    pub fn master(seed: &[u8], version: KeyVersion) -> Option<Self> {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let key = PrivateKey::from_slice(&i[..32])?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        let version = if version.is_private() { version } else { return None };
        Some(Self {
            version,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code,
            material: Material::Private(key),
        })
    }

    /// Decode and fully validate a Base58Check extended key.
    pub fn parse(text: &[u8]) -> Option<Self> {
        let payload = base58::decode_check(text)?;
        Self::from_payload(payload.as_bytes())
    }

    fn from_payload(b: &[u8]) -> Option<Self> {
        if b.len() != PAYLOAD_LEN {
            return None;
        }
        let version = KeyVersion::from_bytes(&b[..4])?;
        let depth = b[4];
        let parent_fingerprint: [u8; 4] = b[5..9].try_into().ok()?;
        let child_number = u32::from_be_bytes(b[9..13].try_into().ok()?);
        if depth == 0 && (parent_fingerprint != [0; 4] || child_number != 0) {
            return None;
        }
        let chain_code: [u8; 32] = b[13..45].try_into().ok()?;
        let key = &b[45..78];
        let material = if version.is_private() {
            if key[0] != 0x00 {
                return None;
            }
            Material::Private(PrivateKey::from_slice(&key[1..])?)
        } else {
            if key[0] != 0x02 && key[0] != 0x03 {
                return None;
            }
            Material::Public(PublicKey::from_slice(key).ok()?)
        };
        Some(Self { version, depth, parent_fingerprint, child_number, chain_code, material })
    }

    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(PAYLOAD_LEN);
        b.extend_from_slice(&self.version.bytes());
        b.push(self.depth);
        b.extend_from_slice(&self.parent_fingerprint);
        b.extend_from_slice(&self.child_number.to_be_bytes());
        b.extend_from_slice(&self.chain_code);
        match &self.material {
            Material::Private(k) => {
                b.push(0);
                b.extend_from_slice(&k.to_bytes());
            }
            Material::Public(p) => b.extend_from_slice(&p.serialize()),
        }
        base58::encode_check(&b)
    }

    pub fn version(&self) -> KeyVersion {
        self.version
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    pub fn is_private(&self) -> bool {
        matches!(self.material, Material::Private(_))
    }

    pub fn private_key(&self) -> Option<&PrivateKey> {
        match &self.material {
            Material::Private(k) => Some(k),
            Material::Public(_) => None,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match &self.material {
            Material::Private(k) => k.public_key(),
            Material::Public(p) => *p,
        }
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public_key().serialize());
        [h[0], h[1], h[2], h[3]]
    }

    /// Neutered (public) copy.
    pub fn to_public(&self) -> Self {
        Self {
            version: self.version.to_public(),
            material: Material::Public(self.public_key()),
            ..*self
        }
    }

    /// Same key under another version (e.g. present a BIP39 master as `zprv`).
    pub fn with_version(&self, version: KeyVersion) -> Option<Self> {
        (version.is_private() == self.is_private()).then_some(Self { version, ..*self })
    }

    /// CKDpriv / CKDpub. `None` for hardened-from-public or the 2^-127 invalid cases.
    pub fn derive_child(&self, index: u32) -> Option<Self> {
        let pk = self.public_key();
        let index_be = index.to_be_bytes();
        let i = match (&self.material, index >= HARDENED) {
            (Material::Public(_), true) => return None,
            (Material::Private(k), true) => {
                hmac_sha512_parts(&self.chain_code, &[&[0u8], &k.to_bytes(), &index_be])
            }
            (_, false) => hmac_sha512_parts(&self.chain_code, &[&pk.serialize(), &index_be]),
        };
        let il: [u8; 32] = i[..32].try_into().ok()?;
        let material = match &self.material {
            Material::Private(k) => Material::Private(k.add_tweak(&il)?),
            Material::Public(p) => {
                let tweak = Scalar::from_be_bytes(il).ok()?;
                Material::Public(p.add_exp_tweak(SECP256K1, &tweak).ok()?)
            }
        };
        Some(Self {
            version: self.version,
            depth: self.depth.checked_add(1)?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: i[32..].try_into().ok()?,
            material,
        })
    }

    pub fn derive_path(&self, path: &[u32]) -> Option<Self> {
        path.iter().try_fold(*self, |k, idx| k.derive_child(*idx))
    }
}

/// Parse `m/44'/0'/0'/0/1` (also `h` for hardened). `None` on malformed input.
pub fn parse_path(text: &str) -> Option<Vec<u32>> {
    let mut parts = text.split('/');
    if parts.next()? != "m" {
        return None;
    }
    parts
        .map(|p| {
            let (num, hard) = match p.strip_suffix(['\'', 'h', 'H']) {
                Some(n) => (n, HARDENED),
                None => (p, 0),
            };
            let n: u32 = num.parse().ok()?;
            (n < HARDENED).then_some(n | hard)
        })
        .collect()
}

pub fn format_path(path: &[u32]) -> String {
    let mut s = String::from("m");
    for idx in path {
        if idx & HARDENED != 0 {
            s.push_str(&format!("/{}'", idx & !HARDENED));
        } else {
            s.push_str(&format!("/{idx}"));
        }
    }
    s
}
