//! Russian text that went through the wrong code page. Sites and programs of the CP1251 era
//! often read UTF-8 bytes as CP1251 and saved the result again as UTF-8, so a search for
//! "фото" is stored as "С„РѕС‚Рѕ". The damage is reversible: such text maps back to CP1251
//! bytes that form valid UTF-8. Ordinary Russian text never does (its CP1251 letters are
//! not UTF-8 continuation bytes), so repairing is safe to apply everywhere.

use encoding_rs::WINDOWS_1251;
use std::borrow::Cow;

/// `text` with one layer of UTF-8-read-as-CP1251 undone; unchanged when it shows none.
pub fn repair_mojibake(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return Cow::Borrowed(text);
    }
    let (bytes, _, unmappable) = WINDOWS_1251.encode(text);
    if unmappable {
        return Cow::Borrowed(text);
    }
    match std::str::from_utf8(&bytes) {
        Ok(fixed) if fixed.chars().count() < text.chars().count() => Cow::Owned(fixed.to_string()),
        _ => Cow::Borrowed(text),
    }
}

/// Bytes of text in an unknown single-byte or UTF-8 encoding: UTF-8 when valid, else CP1251
/// (the ANSI page of the disks this tool reads).
pub fn decode_utf8_or_cp1251(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => WINDOWS_1251.decode_without_bom_handling(bytes).0.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undoes_utf8_read_as_cp1251() {
        assert_eq!(repair_mojibake("С„РѕС‚РѕСЃС‚СЂР°РЅР° РјРѕСЏ СЃС‚СЂР°РЅРёС†Р°"), "фотострана моя страница");
        assert_eq!(repair_mojibake("С‚Р°РЅРіРѕ"), "танго");
    }

    #[test]
    fn leaves_correct_text_alone() {
        for s in ["Привет, мир", "ПРИВЕТ", "ёжик №5", "plain ascii", "naïve café", "日本語"] {
            assert_eq!(repair_mojibake(s), s);
        }
    }

    #[test]
    fn decodes_percent_bytes_in_either_encoding() {
        assert_eq!(decode_utf8_or_cp1251("фото".as_bytes()), "фото");
        assert_eq!(decode_utf8_or_cp1251(&[0xF4, 0xEE, 0xF2, 0xEE]), "фото");
    }
}
