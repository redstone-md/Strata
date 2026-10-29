//! Hash primitives used by every key, address and wallet routine (one implementation each).

use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `SHA256(SHA256(data))`, the Bitcoin checksum/hash.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// `RIPEMD160(SHA256(data))`, the Bitcoin public-key hash.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA512 over the concatenation of `parts`, avoiding a temporary buffer.
pub fn hmac_sha512_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA512 producing 64 bytes (BIP39 / Electrum 2.x seed stretching).
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, &mut out);
    out
}

/// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // hash160 of the generator point (compressed) = pubkey hash of private key 1.
        let g = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(hex::encode(hash160(&g)), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }
}
