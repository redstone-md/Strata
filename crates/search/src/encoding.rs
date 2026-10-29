//! Text encodings a search can look for, defined once: how a query string is encoded into
//! bytes and how bytes around a match are decoded back for display.

use serde::{Deserialize, Serialize};

/// Upper halves (0x80..=0xFF) of the Cyrillic single-byte code pages. U+FFFD marks the one
/// unassigned CP1251 byte.
const CP1251_HIGH: &str = "ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—\u{FFFD}™љ›њќћџ\u{A0}ЎўЈ¤Ґ¦§Ё©Є«¬\u{AD}®Ї°±Ііґµ¶·ё№є»јЅѕї\
АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя";
const CP866_HIGH: &str = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп\
░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■\u{A0}";

/// Shown instead of bytes that are not printable text.
const PLACEHOLDER: char = '·';

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Utf8,
    Ascii,
    Cp1251,
    Cp866,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    pub const ALL: [Encoding; 6] = [Self::Utf8, Self::Ascii, Self::Cp1251, Self::Cp866, Self::Utf16Le, Self::Utf16Be];

    pub fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "UTF-8",
            Self::Ascii => "ASCII",
            Self::Cp1251 => "CP1251",
            Self::Cp866 => "CP866",
            Self::Utf16Le => "UTF-16LE",
            Self::Utf16Be => "UTF-16BE",
        }
    }

    /// Short key used on the command line and in storage: `utf8`, `cp1251`, `utf16le`...
    pub fn key(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Ascii => "ascii",
            Self::Cp1251 => "cp1251",
            Self::Cp866 => "cp866",
            Self::Utf16Le => "utf16le",
            Self::Utf16Be => "utf16be",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        let k = key.trim().to_ascii_lowercase().replace(['-', '_'], "");
        Self::ALL.into_iter().find(|e| e.key() == k)
    }

    fn high_table(self) -> Option<&'static str> {
        match self {
            Self::Cp1251 => Some(CP1251_HIGH),
            Self::Cp866 => Some(CP866_HIGH),
            _ => None,
        }
    }

    /// Bytes of `text` in this encoding, or `None` when it cannot represent every character.
    pub fn encode(self, text: &str) -> Option<Vec<u8>> {
        match self {
            Self::Utf8 => Some(text.as_bytes().to_vec()),
            Self::Ascii => text.is_ascii().then(|| text.as_bytes().to_vec()),
            Self::Utf16Le => Some(text.encode_utf16().flat_map(u16::to_le_bytes).collect()),
            Self::Utf16Be => Some(text.encode_utf16().flat_map(u16::to_be_bytes).collect()),
            Self::Cp1251 | Self::Cp866 => {
                let table = self.high_table()?;
                text.chars()
                    .map(|c| if c.is_ascii() { Some(c as u8) } else { table.chars().position(|t| t == c).map(|i| 0x80 + i as u8) })
                    .collect()
            }
        }
    }

    /// Bytes per code unit (where a match may start).
    pub fn unit(self) -> usize {
        match self {
            Self::Utf16Le | Self::Utf16Be => 2,
            _ => 1,
        }
    }

    /// Decode bytes for display; anything not printable becomes `·`, one per unit.
    pub fn decode(self, bytes: &[u8]) -> String {
        let shown = |c: char| if c.is_control() || c == '\u{FFFD}' { PLACEHOLDER } else { c };
        match self {
            Self::Utf8 => String::from_utf8_lossy(bytes).chars().map(shown).collect(),
            Self::Ascii => bytes.iter().map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { PLACEHOLDER }).collect(),
            Self::Cp1251 | Self::Cp866 => {
                let table: Vec<char> = self.high_table().unwrap_or_default().chars().collect();
                bytes.iter().map(|b| if *b < 0x80 { shown(*b as char) } else { table.get(usize::from(*b - 0x80)).copied().map_or(PLACEHOLDER, shown) }).collect()
            }
            Self::Utf16Le | Self::Utf16Be => {
                let units = bytes.chunks_exact(2).map(|c| if self == Self::Utf16Le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) });
                char::decode_utf16(units).map(|r| r.map_or(PLACEHOLDER, shown)).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_cover_the_upper_half() {
        assert_eq!(CP1251_HIGH.chars().count(), 128);
        assert_eq!(CP866_HIGH.chars().count(), 128);
    }

    #[test]
    fn cyrillic_round_trips() {
        let word = "Пароль Ёж";
        assert_eq!(Encoding::Cp1251.encode(word).unwrap(), b"\xCF\xE0\xF0\xEE\xEB\xFC \xA8\xE6");
        assert_eq!(Encoding::Cp866.encode(word).unwrap(), b"\x8F\xA0\xE0\xAE\xAB\xEC \xF0\xA6");
        for e in Encoding::ALL.into_iter().filter(|e| *e != Encoding::Ascii) {
            assert_eq!(e.decode(&e.encode(word).unwrap()), word, "{e:?}");
        }
        assert!(Encoding::Ascii.encode(word).is_none());
        assert!(Encoding::Cp1251.encode("日本").is_none());
        assert_eq!(Encoding::Ascii.decode(b"a\x00b\n"), "a·b·");
        assert_eq!(Encoding::from_key("UTF-16LE"), Some(Encoding::Utf16Le));
    }
}
