use super::{base58, AddressSet, Network, PrivateKey};

/// Wallet Import Format private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wif {
    key: PrivateKey,
    network: Network,
    compressed: bool,
}

impl Wif {
    pub fn new(key: PrivateKey, network: Network, compressed: bool) -> Self {
        Self { key, network, compressed }
    }

    /// Decode and validate (checksum, prefix, length, compression flag, scalar range).
    pub fn parse(text: &[u8]) -> Option<Self> {
        let payload = base58::decode_check(text)?;
        let bytes = payload.as_bytes();
        let network = Network::from_wif_prefix(*bytes.first()?)?;
        let compressed = match bytes.len() {
            33 => false,
            34 if bytes[33] == 0x01 => true,
            _ => return None,
        };
        let key = PrivateKey::from_slice(&bytes[1..33])?;
        Some(Self { key, network, compressed })
    }

    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(34);
        data.push(self.network.wif_prefix());
        data.extend_from_slice(&self.key.to_bytes());
        if self.compressed {
            data.push(0x01);
        }
        base58::encode_check(&data)
    }

    pub fn key(&self) -> &PrivateKey {
        &self.key
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn addresses(&self) -> AddressSet {
        AddressSet::from_private_key(&self.key, self.network)
    }

    /// Human label such as `WIF compressed mainnet`.
    pub fn describe(&self) -> String {
        let form = if self.compressed { "compressed" } else { "uncompressed" };
        format!("WIF {form} {}", self.network.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_one_roundtrip() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let key = PrivateKey::from_bytes(&one).unwrap();
        let u = Wif::new(key, Network::Mainnet, false).encode();
        let c = Wif::new(key, Network::Mainnet, true).encode();
        assert_eq!(u, "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
        assert_eq!(c, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
        let parsed = Wif::parse(c.as_bytes()).unwrap();
        assert!(parsed.compressed());
        assert_eq!(parsed.addresses().p2pkh_compressed(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        let parsed = Wif::parse(u.as_bytes()).unwrap();
        assert_eq!(parsed.addresses().p2pkh_uncompressed(), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        let t = Wif::new(key, Network::Testnet, true).encode();
        assert_eq!(&t[..1], "c");
        assert_eq!(Wif::parse(t.as_bytes()).unwrap().network(), Network::Testnet);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Wif::parse(b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWo").is_none());
        assert!(Wif::parse(b"").is_none());
    }
}
