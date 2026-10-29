//! SEC1 / OpenSSL DER encodings of secp256k1 private keys (as written by Bitcoin Core,
//! OpenSSL and KeyHunter-style dumps). One parser shared by the DER detector and wallet.dat.

use super::PrivateKey;
use serde::Serialize;

/// `version INTEGER 1, privateKey OCTET STRING (32)`: common to every form.
pub const DER_CORE: &[u8] = &[0x02, 0x01, 0x01, 0x04, 0x20];
const CURVE_OID: &[u8] = &[0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];
const PUB_UNCOMPRESSED: &[u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00];
const PUB_COMPRESSED: &[u8] = &[0xa1, 0x24, 0x03, 0x22, 0x00];
/// secp256k1 field prime, embedded in explicit-parameter encodings.
const FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerForm {
    /// `30 74`: named curve + uncompressed public key (118 bytes).
    NamedUncompressed,
    /// `30 54`: named curve + compressed public key (86 bytes).
    NamedCompressed,
    /// `30 2e`: named curve, no public key (48 bytes).
    NamedShort,
    /// `30 82 01 13`: explicit curve parameters + uncompressed key (279 bytes, Bitcoin Core).
    ExplicitUncompressed,
    /// `30 81 d3`: explicit curve parameters + compressed key (214 bytes, Bitcoin Core).
    ExplicitCompressed,
}

struct Layout {
    form: DerForm,
    header: &'static [u8],
    total: usize,
}

const LAYOUTS: &[Layout] = &[
    Layout { form: DerForm::NamedUncompressed, header: &[0x30, 0x74], total: 118 },
    Layout { form: DerForm::NamedCompressed, header: &[0x30, 0x54], total: 86 },
    Layout { form: DerForm::NamedShort, header: &[0x30, 0x2e], total: 48 },
    Layout { form: DerForm::ExplicitUncompressed, header: &[0x30, 0x82, 0x01, 0x13], total: 279 },
    Layout { form: DerForm::ExplicitCompressed, header: &[0x30, 0x81, 0xd3], total: 214 },
];

/// Longest DER form, plus a one-byte KeyHunter prefix.
pub const MAX_DER_LEN: usize = 280;

impl DerForm {
    pub fn total_len(self) -> usize {
        LAYOUTS.iter().find(|l| l.form == self).map_or(0, |l| l.total)
    }

    pub fn compressed(self) -> bool {
        matches!(self, DerForm::NamedCompressed | DerForm::ExplicitCompressed)
    }

    fn explicit(self) -> bool {
        matches!(self, DerForm::ExplicitUncompressed | DerForm::ExplicitCompressed)
    }

    fn has_pubkey(self) -> bool {
        self != DerForm::NamedShort
    }

    pub fn name(self) -> &'static str {
        match self {
            DerForm::NamedUncompressed => "sec1-named-uncompressed",
            DerForm::NamedCompressed => "sec1-named-compressed",
            DerForm::NamedShort => "sec1-named-short",
            DerForm::ExplicitUncompressed => "openssl-explicit-uncompressed",
            DerForm::ExplicitCompressed => "openssl-explicit-compressed",
        }
    }
}

/// Result of validating a DER private key.
#[derive(Debug, Clone)]
pub struct DerKey {
    key: PrivateKey,
    form: DerForm,
    curve_ok: bool,
    /// `Some(true)` when the embedded public key equals `key*G`.
    pubkey_match: Option<bool>,
}

impl DerKey {
    /// Parse a key whose `30 ..` header starts at `data[0]`. Trailing bytes are ignored.
    pub fn parse(data: &[u8]) -> Option<Self> {
        LAYOUTS.iter().find_map(|l| Self::parse_layout(data, l))
    }

    /// Given the offset of [`DER_CORE`] inside `data`, find the enclosing structure.
    /// Returns the start offset of the `30` header and the key.
    pub fn parse_around_core(data: &[u8], core_at: usize) -> Option<(usize, Self)> {
        LAYOUTS.iter().find_map(|l| {
            let start = core_at.checked_sub(l.header.len())?;
            Self::parse_layout(data.get(start..)?, l).map(|k| (start, k))
        })
    }

    fn parse_layout(data: &[u8], layout: &Layout) -> Option<Self> {
        if !data.starts_with(layout.header) {
            return None;
        }
        let body = data.get(..layout.total)?;
        let core = layout.header.len();
        if body.get(core..core + DER_CORE.len())? != DER_CORE {
            return None;
        }
        let scalar_at = core + DER_CORE.len();
        let key = PrivateKey::from_slice(body.get(scalar_at..scalar_at + 32)?)?;
        let form = layout.form;
        let rest = body.get(scalar_at + 32..)?;
        let curve_ok = if form.explicit() {
            memchr::memmem::find(rest, &FIELD_PRIME).is_some()
        } else {
            rest.starts_with(CURVE_OID)
        };
        let pubkey_match = form.has_pubkey().then(|| Self::check_pubkey(body, form, &key));
        Some(Self { key, form, curve_ok, pubkey_match })
    }

    fn check_pubkey(body: &[u8], form: DerForm, key: &PrivateKey) -> bool {
        let (tag, point_len) =
            if form.compressed() { (PUB_COMPRESSED, 33) } else { (PUB_UNCOMPRESSED, 65) };
        let tag_at = body.len().saturating_sub(tag.len() + point_len);
        if body.get(tag_at..tag_at + tag.len()) != Some(tag) {
            return false;
        }
        let embedded = &body[tag_at + tag.len()..];
        let pk = key.public_key();
        if form.compressed() {
            embedded == pk.serialize().as_slice()
        } else {
            embedded == pk.serialize_uncompressed().as_slice()
        }
    }

    pub fn key(&self) -> &PrivateKey {
        &self.key
    }

    pub fn form(&self) -> DerForm {
        self.form
    }

    /// Encoded length in bytes.
    pub fn encoded_len(&self) -> usize {
        self.form.total_len()
    }

    pub fn curve_ok(&self) -> bool {
        self.curve_ok
    }

    pub fn pubkey_match(&self) -> Option<bool> {
        self.pubkey_match
    }

    /// Whether the public key embedded in the encoding is compressed.
    pub fn compressed(&self) -> bool {
        self.form.compressed()
    }
}

/// Build a DER key in the requested form (fixtures and wallet re-export).
pub fn encode(key: &PrivateKey, form: DerForm) -> Vec<u8> {
    let layout = LAYOUTS.iter().find(|l| l.form == form).unwrap_or(&LAYOUTS[0]);
    let mut out = layout.header.to_vec();
    out.extend_from_slice(DER_CORE);
    out.extend_from_slice(&key.to_bytes());
    let pk_len = match form {
        DerForm::NamedShort => 0,
        f if f.compressed() => PUB_COMPRESSED.len() + 33,
        _ => PUB_UNCOMPRESSED.len() + 65,
    };
    if form.explicit() {
        // Minimal explicit-parameter filler carrying the field prime, padded to size.
        let mut params = vec![0u8; layout.total - out.len() - pk_len];
        if params.len() >= FIELD_PRIME.len() {
            params[..FIELD_PRIME.len()].copy_from_slice(&FIELD_PRIME);
        }
        out.extend_from_slice(&params);
    } else {
        out.extend_from_slice(CURVE_OID);
    }
    let pk = key.public_key();
    match form {
        DerForm::NamedShort => {}
        f if f.compressed() => {
            out.extend_from_slice(PUB_COMPRESSED);
            out.extend_from_slice(&pk.serialize());
        }
        _ => {
            out.extend_from_slice(PUB_UNCOMPRESSED);
            out.extend_from_slice(&pk.serialize_uncompressed());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PrivateKey {
        PrivateKey::from_hex(b"0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
            .unwrap()
    }

    #[test]
    fn every_form_roundtrips() {
        let key = key();
        for l in LAYOUTS {
            let der = encode(&key, l.form);
            assert_eq!(der.len(), l.total, "{:?}", l.form);
            let parsed = DerKey::parse(&der).unwrap();
            assert_eq!(parsed.form(), l.form);
            assert_eq!(parsed.key(), &key);
            assert!(parsed.curve_ok());
            assert_eq!(parsed.pubkey_match(), l.form.has_pubkey().then_some(true));
            let core = memchr::memmem::find(&der, DER_CORE).unwrap();
            assert_eq!(DerKey::parse_around_core(&der, core).unwrap().0, 0);
        }
    }

    #[test]
    fn mismatched_pubkey_and_truncation() {
        let mut der = encode(&key(), DerForm::NamedCompressed);
        let last = der.len() - 1;
        der[last] ^= 1;
        assert_eq!(DerKey::parse(&der).unwrap().pubkey_match(), Some(false));
        assert!(DerKey::parse(&der[..50]).is_none());
    }
}
