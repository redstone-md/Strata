//! BIP39 mnemonics: checksum validation in every language and seed derivation.

use super::wordlists::{WordIndex, BIP39_LANGS};
use crate::keys::hash::{pbkdf2_sha512, sha256};
use unicode_normalization::UnicodeNormalization;

/// Valid BIP39 phrase lengths.
pub const BIP39_LENGTHS: [usize; 5] = [12, 15, 18, 21, 24];

/// A checksum-valid BIP39 mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip39Mnemonic {
    lang: usize,
    indices: Vec<u16>,
}

impl Bip39Mnemonic {
    /// Parse a whitespace-separated phrase; the language is detected.
    pub fn parse(phrase: &str) -> Option<Self> {
        let words: Vec<String> = phrase.split_whitespace().map(|w| w.to_lowercase()).collect();
        let index = WordIndex::get();
        let entries: Option<Vec<_>> = words.iter().map(|w| index.lookup(w.as_bytes())).collect();
        let entries = entries?;
        let mask = entries.iter().fold(u16::MAX, |m, e| m & e.mask());
        (0..BIP39_LANGS).filter(|l| mask & (1 << l) != 0).find_map(|lang| {
            let idx: Option<Vec<u16>> = entries.iter().map(|e| e.bip39_index(lang)).collect();
            Self::from_indices(lang, &idx?)
        })
    }

    /// Validate word indices of language `lang` (checksum included).
    pub fn from_indices(lang: usize, indices: &[u16]) -> Option<Self> {
        checksum_ok(indices).then(|| Self { lang, indices: indices.to_vec() })
    }

    pub fn word_count(&self) -> usize {
        self.indices.len()
    }

    pub fn language(&self) -> &'static str {
        WordIndex::language_name(self.lang)
    }

    /// Canonical phrase (wordlist spelling, single spaces).
    pub fn phrase(&self) -> String {
        let words: Vec<&str> = self
            .indices
            .iter()
            .filter_map(|i| WordIndex::bip39_word(self.lang, *i))
            .collect();
        words.join(" ")
    }

    pub fn entropy(&self) -> Vec<u8> {
        let (bits, _) = pack_bits(&self.indices);
        let ent_bytes = self.indices.len() * 11 * 32 / 33 / 8;
        bits[..ent_bytes].to_vec()
    }

    /// `PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic" + NFKD(passphrase), 2048)`.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let phrase: String = self.phrase().nfkd().collect();
        let salt: String = format!("mnemonic{passphrase}").nfkd().collect();
        pbkdf2_sha512(phrase.as_bytes(), salt.as_bytes(), 2048)
    }
}

/// Pack 11-bit indices big-endian; returns bytes and total bit count.
fn pack_bits(indices: &[u16]) -> ([u8; 33], usize) {
    let mut out = [0u8; 33];
    let mut bit = 0usize;
    for idx in indices {
        for b in (0..11).rev() {
            if (idx >> b) & 1 == 1 {
                if let Some(byte) = out.get_mut(bit / 8) {
                    *byte |= 0x80 >> (bit % 8);
                }
            }
            bit += 1;
        }
    }
    (out, bit)
}

/// Checksum check without allocation. Hot path of the mnemonic detector.
pub fn checksum_ok(indices: &[u16]) -> bool {
    if !BIP39_LENGTHS.contains(&indices.len()) || indices.iter().any(|i| *i >= 2048) {
        return false;
    }
    let (bits, total) = pack_bits(indices);
    let cs_bits = total / 33;
    let ent_bytes = (total - cs_bits) / 8;
    let hash = sha256(&bits[..ent_bytes]);
    let want = hash[0] >> (8 - cs_bits);
    let have = if cs_bits == 8 { bits[ent_bytes] } else { bits[ent_bytes] >> (8 - cs_bits) };
    want == have
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official vectors (trezor/python-mnemonic), passphrase "TREZOR".
    const VECTORS: &[(&str, &str, &str)] = &[
        ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow", "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when", "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528"),
        ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold", "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"),
    ];

    #[test]
    fn official_vectors() {
        for (entropy, phrase, seed) in VECTORS {
            let m = Bip39Mnemonic::parse(phrase).unwrap();
            assert_eq!(m.language(), "english");
            assert_eq!(hex::encode(m.entropy()), *entropy);
            assert_eq!(hex::encode(m.to_seed("TREZOR")), *seed);
            assert_eq!(&m.phrase(), phrase);
        }
    }

    #[test]
    fn bad_checksum_and_length() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Bip39Mnemonic::parse(bad).is_none());
        assert!(Bip39Mnemonic::parse("abandon about").is_none());
        assert!(Bip39Mnemonic::parse("").is_none());
    }

    #[test]
    fn other_languages() {
        // Japanese vector (ideographic spaces) from the official list.
        let ja = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら";
        let m = Bip39Mnemonic::parse(ja).unwrap();
        assert_eq!(m.language(), "japanese");
        let es = "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto";
        assert_eq!(Bip39Mnemonic::parse(es).unwrap().language(), "spanish");
    }
}
