//! MultiBit Classic private key export (`.key`): plaintext WIF list or OpenSSL-encrypted blob.

use super::report::{CrackHash, RecoveredKey, WalletKind, WalletReport};
use crate::keys::Wif;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;

const HEADER: &[u8] = b"# KEEP YOUR PRIVATE KEYS SAFE";
const FOOTER: &[u8] = b"# End of private keys";
/// Base64 of OpenSSL's `Salted__` prefix.
const SALTED_B64: &[u8] = b"U2FsdGVkX1";

pub fn looks_like(data: &[u8]) -> bool {
    let text = skip_ws(data);
    text.starts_with(HEADER) || text.starts_with(SALTED_B64) || memchr::memmem::find(data, FOOTER).is_some()
}

fn skip_ws(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    data.get(start..).unwrap_or(&[])
}

pub fn parse(data: &[u8]) -> Option<WalletReport> {
    let text = skip_ws(data);
    if text.starts_with(SALTED_B64) {
        return parse_encrypted(text);
    }
    if !looks_like(data) {
        return None;
    }
    let mut report = WalletReport::new(WalletKind::MultiBitClassic);
    report.set_encrypted(false);
    let mut bad_lines = 0usize;
    for line in text.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut parts = line.split(|b| *b == b' ').filter(|p| !p.is_empty());
        let Some(wif) = parts.next() else { continue };
        match Wif::parse(wif) {
            Some(w) => {
                let created = parts.next().map(|t| String::from_utf8_lossy(t).into_owned());
                let source = created.map_or_else(|| "key export".to_string(), |t| format!("key export {t}"));
                report.add_key(RecoveredKey::plain(source, *w.key(), w.compressed(), w.network()));
            }
            None => bad_lines += 1,
        }
    }
    report.set_meta("unparsed_lines", json!(bad_lines));
    report.set_meta("complete", json!(memchr::memmem::find(data, FOOTER).is_some()));
    Some(report)
}

fn parse_encrypted(text: &[u8]) -> Option<WalletReport> {
    let compact: Vec<u8> = text.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut report = WalletReport::new(WalletKind::MultiBitClassic);
    report.set_encrypted(true);
    // Truncated files: decode the longest valid base64 prefix.
    let usable = compact.len() / 4 * 4;
    let raw = B64.decode(compact.get(..usable)?).ok()?;
    if let (Some(b"Salted__"), Some(salt), Some(ct)) = (raw.get(..8), raw.get(8..16), raw.get(16..48)) {
        report.set_crack_hash(CrackHash::new(
            format!("$multibit$1*{}*{}", hex::encode(salt), hex::encode(ct)),
            "hashcat -m 22500",
        ));
    }
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_export() {
        let text = "# KEEP YOUR PRIVATE KEYS SAFE !\n# header\nKwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn 2013-04-01T10:00:00Z\r\n# End of private keys\n";
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.plain_key_count(), 1);
        assert_eq!(r.addresses()[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn encrypted_export() {
        let mut raw = b"Salted__".to_vec();
        raw.extend([0xaa; 8]);
        raw.extend([0xbb; 64]);
        let text = B64.encode(&raw);
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.encrypted(), Some(true));
        assert_eq!(r.crack_hash().unwrap().hash(), format!("$multibit$1*{}*{}", "aa".repeat(8), "bb".repeat(32)));
    }
}
