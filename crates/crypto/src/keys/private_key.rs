use secp256k1::{PublicKey, Scalar, SecretKey};
use std::fmt;

/// A valid secp256k1 private scalar in `1..n-1`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Validates the range; `None` for zero or values `>= n`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        SecretKey::from_slice(bytes).ok().map(Self)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: &[u8; 32] = bytes.try_into().ok()?;
        Self::from_bytes(arr)
    }

    /// Parse 64 hex digits (either case).
    pub fn from_hex(text: &[u8]) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).ok()?;
        Self::from_bytes(&bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key_global(&self.0)
    }

    /// `(self + tweak) mod n`, `None` if the tweak is out of range or the sum is zero.
    pub fn add_tweak(&self, tweak: &[u8; 32]) -> Option<Self> {
        let scalar = Scalar::from_be_bytes(*tweak).ok()?;
        self.0.add_tweak(&scalar).ok().map(Self)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Recovery tool: values are shown in clear by design.
        write!(f, "PrivateKey({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    #[test]
    fn range_is_validated() {
        assert!(PrivateKey::from_bytes(&[0u8; 32]).is_none());
        assert!(PrivateKey::from_hex(N.as_bytes()).is_none());
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(PrivateKey::from_bytes(&one).is_some());
        let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        assert!(PrivateKey::from_hex(n_minus_1.as_bytes()).is_some());
        assert!(PrivateKey::from_hex(b"zz").is_none());
    }
}
