//! Base58Check: the single implementation used for WIF, addresses and extended keys.

/// Longest Base58Check string we ever decode (extended keys are 111 chars).
pub const MAX_ENCODED_LEN: usize = 128;

/// Base58 alphabet membership, indexed by byte.
pub static BASE58_CLASS: [bool; 256] = {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut table = [false; 256];
    let mut i = 0;
    while i < alphabet.len() {
        table[alphabet[i] as usize] = true;
        i += 1;
    }
    table
};

pub fn is_base58(text: &[u8]) -> bool {
    text.iter().all(|b| BASE58_CLASS[*b as usize])
}

/// Decoded Base58Check payload held on the stack (no allocation on the hot path).
#[derive(Clone, Copy)]
pub struct Payload {
    buf: [u8; MAX_ENCODED_LEN],
    len: usize,
}

impl Payload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Decode and verify a Base58Check string. `None` on bad alphabet, length or checksum.
pub fn decode_check(text: &[u8]) -> Option<Payload> {
    if text.is_empty() || text.len() > MAX_ENCODED_LEN {
        return None;
    }
    let mut buf = [0u8; MAX_ENCODED_LEN];
    let len = bs58::decode(text).with_check(None).onto(&mut buf[..]).ok()?;
    Some(Payload { buf, len })
}

/// Encode `payload` with a 4-byte double-SHA256 checksum.
pub fn encode_check(payload: &[u8]) -> String {
    bs58::encode(payload).with_check().into_string()
}

/// Encode `version || payload` with checksum.
pub fn encode_check_versioned(version: &[u8], payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(version.len() + payload.len());
    data.extend_from_slice(version);
    data.extend_from_slice(payload);
    encode_check(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_checksum() {
        let s = encode_check(&[0x00; 21]);
        assert_eq!(s, "1111111111111111111114oLvT2");
        assert_eq!(decode_check(s.as_bytes()).unwrap().as_bytes(), &[0u8; 21]);
        assert!(decode_check(b"1111111111111111111114oLvT3").is_none());
        assert!(decode_check(b"0OIl").is_none());
        assert!(decode_check(b"").is_none());
    }
}
