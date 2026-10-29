//! Text: encoding detection (ASCII, UTF-8, UTF-16 LE/BE with or without BOM, CP1251) and
//! content classification (HTML, XML, JSON, Electrum wallet, e-mail, plain text).

use crate::probe::Probe;
use crate::profile::{BLOCK, BlockClass, text_ratio};
use crate::registry::TypeId;
use serde::{Deserialize, Serialize};
use strata_kernel::Confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Utf16LeBom,
    Utf16BeBom,
    /// Windows Cyrillic.
    Cp1251,
    /// Some other single-byte code page (Latin-1 / CP1252 assumed).
    Latin1,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Utf8 => "utf-8",
            Encoding::Utf8Bom => "utf-8-bom",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Utf16LeBom => "utf-16le-bom",
            Encoding::Utf16BeBom => "utf-16be-bom",
            Encoding::Cp1251 => "cp1251",
            Encoding::Latin1 => "latin1",
        }
    }

    /// Detect the encoding of `data`, or `None` when it does not look like text.
    pub fn detect(data: &[u8]) -> Option<Encoding> {
        if data.starts_with(b"\xEF\xBB\xBF") {
            return Some(Encoding::Utf8Bom);
        }
        if data.starts_with(b"\xFF\xFE") {
            return Some(Encoding::Utf16LeBom);
        }
        if data.starts_with(b"\xFE\xFF") {
            return Some(Encoding::Utf16BeBom);
        }
        if data.is_empty() || text_ratio(data) < 0.97 {
            return None;
        }
        let zeros_odd = data.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
        let zeros_even = data.iter().step_by(2).filter(|b| **b == 0).count();
        let half = data.len() / 2;
        if zeros_odd * 10 >= half * 3 && zeros_odd > zeros_even * 4 {
            return Some(Encoding::Utf16Le);
        }
        if zeros_even * 10 >= half * 3 && zeros_even > zeros_odd * 4 {
            return Some(Encoding::Utf16Be);
        }
        if data.contains(&0) {
            return None;
        }
        match std::str::from_utf8(data) {
            Ok(s) if s.is_ascii() => Some(Encoding::Ascii),
            Ok(_) => Some(Encoding::Utf8),
            // Truncated multi-byte sequence at the very end is still UTF-8.
            Err(e) if e.error_len().is_none() && e.valid_up_to() > 0 => Some(Encoding::Utf8),
            Err(_) => Some(Self::single_byte(data)),
        }
    }

    fn single_byte(data: &[u8]) -> Encoding {
        let high: Vec<u8> = data.iter().copied().filter(|b| *b >= 0x80).collect();
        let cyrillic = high.iter().filter(|b| **b >= 0xC0 || **b == 0xA8 || **b == 0xB8).count();
        if !high.is_empty() && cyrillic * 10 >= high.len() * 7 {
            Encoding::Cp1251
        } else {
            Encoding::Latin1
        }
    }

    /// Decode at most `limit` bytes into a `String`, replacing invalid sequences.
    pub fn decode(self, data: &[u8], limit: usize) -> String {
        let data = &data[..data.len().min(limit)];
        match self {
            Encoding::Ascii | Encoding::Utf8 => String::from_utf8_lossy(data).into_owned(),
            Encoding::Utf8Bom => String::from_utf8_lossy(data.get(3..).unwrap_or_default()).into_owned(),
            Encoding::Utf16Le => utf16(data, u16::from_le_bytes),
            Encoding::Utf16LeBom => utf16(data.get(2..).unwrap_or_default(), u16::from_le_bytes),
            Encoding::Utf16Be => utf16(data, u16::from_be_bytes),
            Encoding::Utf16BeBom => utf16(data.get(2..).unwrap_or_default(), u16::from_be_bytes),
            Encoding::Cp1251 => data.iter().map(|b| cp1251(*b)).collect(),
            Encoding::Latin1 => data.iter().map(|b| char::from(*b)).collect(),
        }
    }
}

fn utf16(data: &[u8], conv: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| conv(*c)).collect();
    String::from_utf16_lossy(&units)
}

fn cp1251(b: u8) -> char {
    match b {
        0x00..=0x7F => char::from(b),
        0xC0..=0xFF => char::from_u32(0x0410 + u32::from(b - 0xC0)).unwrap_or('\u{FFFD}'),
        0xA8 => 'Ё',
        0xB8 => 'ё',
        0xB9 => '№',
        0x85 => '…',
        0x96 => '–',
        0x97 => '—',
        0xAB => '«',
        0xBB => '»',
        0x93 | 0x94 => '"',
        0x91 | 0x92 => '\'',
        0xA0 => ' ',
        _ => '\u{FFFD}',
    }
}

const SAMPLE: usize = 256 * 1024;
const MAIL_HEADERS: &[&str] = &[
    "from", "to", "subject", "date", "received", "message-id", "mime-version", "return-path",
    "delivered-to", "content-type", "reply-to", "cc", "x-mailer",
];

/// Validator shared by all text types: decode, classify, measure how much of it is text.
pub fn validate(data: &[u8]) -> Option<Probe> {
    // Measure on non-zero blocks so a half-zeroed text file is still recognised.
    let mut content = 0usize;
    let mut texty = 0usize;
    let mut sample = Vec::new();
    for block in data.chunks(BLOCK) {
        let class = BlockClass::classify(block);
        if matches!(class, BlockClass::Zero) {
            continue;
        }
        content += 1;
        if matches!(class, BlockClass::Text) || text_ratio(block) >= 0.97 {
            texty += 1;
            if sample.len() < SAMPLE {
                sample.extend_from_slice(block);
            }
        }
    }
    if content == 0 || texty * 10 < content * 6 {
        return None;
    }
    let encoding = Encoding::detect(sample.get(..sample.len().min(64 * 1024)).unwrap_or_default())?;
    let text = encoding.decode(&sample, SAMPLE);
    let mut probe = classify(&text);
    probe = probe.with_structure(texty as f32 / content as f32);
    probe.property("encoding", encoding.name());
    if let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty()) {
        let preview: String = line.chars().take(80).collect();
        probe.property("first_line", preview);
    }
    Some(probe)
}

/// Decide which text type `text` is.
pub fn classify(text: &str) -> Probe {
    let t = text.trim_start_matches(['\u{FEFF}', ' ', '\t', '\r', '\n']);
    let head: String = t.chars().take(4096).collect::<String>().to_ascii_lowercase();
    if (t.starts_with('{') || t.starts_with('['))
        && (t.contains("\"keystore\"") || t.contains("\"seed_version\"") || t.contains("'seed_version'"))
    {
        return electrum(t);
    }
    if head.contains("<!doctype html") || head.contains("<html") || (t.starts_with('<') && head.contains("<body")) {
        return Probe::new(TypeId::Html, Confidence::new(0.85));
    }
    if t.starts_with("<?xml") || (t.starts_with('<') && t.trim_end().ends_with('>')) {
        return Probe::new(TypeId::Xml, Confidence::new(0.85));
    }
    if t.starts_with('{') || t.starts_with('[') {
        return json(t);
    }
    if let Some(probe) = mail(t) {
        return probe;
    }
    Probe::new(TypeId::Text, Confidence::new(0.7))
}

fn json(t: &str) -> Probe {
    match serde_json::from_str::<serde_json::Value>(t) {
        Ok(_) => Probe::new(TypeId::Json, Confidence::new(0.9)),
        Err(e) if e.is_eof() => {
            let mut p = Probe::new(TypeId::Json, Confidence::new(0.75));
            p.note("JSON truncated");
            p
        }
        Err(_) if t.matches("\":").count() >= 2 => {
            let mut p = Probe::new(TypeId::Json, Confidence::new(0.6)).with_structure(0.5);
            p.note("JSON does not parse completely");
            p
        }
        Err(_) => Probe::new(TypeId::Text, Confidence::new(0.6)),
    }
}

fn electrum(t: &str) -> Probe {
    let mut p = Probe::new(TypeId::ElectrumWallet, Confidence::new(0.95));
    for key in ["keystore", "seed_version", "wallet_type", "use_encryption", "addresses", "x1/", "master_public_keys"] {
        if t.contains(&format!("\"{key}")) || t.contains(&format!("'{key}")) {
            p.property("key", key);
        }
    }
    if t.contains("\"use_encryption\": true") || t.contains("'use_encryption': True") {
        p.note("wallet secrets are password-encrypted");
    }
    if serde_json::from_str::<serde_json::Value>(t).is_err() {
        p = p.with_structure(0.7);
        p.note("wallet JSON incomplete or damaged");
    }
    p
}

/// RFC 822 message or mbox: leading `Name: value` header lines with known mail headers.
fn mail(t: &str) -> Option<Probe> {
    let mbox = t.starts_with("From ");
    let mut known = 0;
    let mut headers = 0;
    let mut subject = None;
    for line in t.lines().skip(usize::from(mbox)).take(80) {
        if line.trim().is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else { break };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            break;
        }
        headers += 1;
        let lower = name.to_ascii_lowercase();
        if MAIL_HEADERS.contains(&lower.as_str()) {
            known += 1;
        }
        if lower == "subject" {
            subject = Some(value.trim().chars().take(120).collect::<String>());
        }
    }
    if headers < 3 || known < 2 {
        return None;
    }
    let id = if mbox { TypeId::Mbox } else { TypeId::Eml };
    let mut p = Probe::new(id, Confidence::new(0.85));
    if let Some(s) = subject {
        p.property("subject", s);
    }
    if mbox {
        p.item(crate::InnerKind::Object, format!("{} messages", t.matches("\nFrom ").count() + 1), None);
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_encodings() {
        assert_eq!(Encoding::detect(b"hello world\n"), Some(Encoding::Ascii));
        assert_eq!(Encoding::detect("привет мир".as_bytes()), Some(Encoding::Utf8));
        let le: Vec<u8> = "hello world".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(Encoding::detect(&le), Some(Encoding::Utf16Le));
        let be: Vec<u8> = "hello world".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(Encoding::detect(&be), Some(Encoding::Utf16Be));
        // "Привет мир, это тест" in CP1251.
        let cp: Vec<u8> = vec![
            0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, 0x20, 0xEC, 0xE8, 0xF0, 0x2C, 0x20, 0xFD, 0xF2, 0xEE, 0x20,
            0xF2, 0xE5, 0xF1, 0xF2,
        ];
        assert_eq!(Encoding::detect(&cp), Some(Encoding::Cp1251));
        assert!(Encoding::Cp1251.decode(&cp, 100).starts_with("Привет"));
        assert_eq!(Encoding::detect(&[0u8, 1, 2, 3, 0x90, 0x80]), None);
    }

    #[test]
    fn classifies() {
        assert_eq!(classify("{\"seed_version\": 18, \"keystore\": {}}").id(), TypeId::ElectrumWallet);
        assert_eq!(classify("<!DOCTYPE html><html></html>").id(), TypeId::Html);
        assert_eq!(classify("<?xml version=\"1.0\"?><a/>").id(), TypeId::Xml);
        assert_eq!(classify("{\"a\": [1, 2]}").id(), TypeId::Json);
        let eml = "From: a@b.c\r\nTo: d@e.f\r\nSubject: hi\r\nDate: Mon\r\n\r\nbody";
        assert_eq!(classify(eml).id(), TypeId::Eml);
        assert_eq!(classify("just some notes\nabout things").id(), TypeId::Text);
    }
}
