//! blockchain.info (Blockchain.com) `wallet.aes.json`: v2/v3 JSON envelopes and v1 raw blobs.

use super::report::{CrackHash, WalletKind, WalletReport};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

pub fn looks_like(data: &[u8]) -> bool {
    let has = |k: &str| memchr::memmem::find(data, k.as_bytes()).is_some();
    has("\"payload\"") && (has("\"guid\"") || has("\"pbkdf2_iterations\"") || has("\"version\""))
}

/// Parse a JSON envelope, or (less certain) a bare base64 v1 blob.
pub fn parse(data: &[u8]) -> Option<WalletReport> {
    match serde_json::from_slice::<Value>(data) {
        Ok(Value::Object(obj)) => {
            let payload = obj.get("payload")?.as_str()?;
            let mut report = base_report();
            let iterations = obj.get("pbkdf2_iterations").and_then(Value::as_u64).unwrap_or(5000);
            for k in ["guid", "version", "pbkdf2_iterations"] {
                if let Some(v) = obj.get(k) {
                    report.set_meta(k, v.clone());
                }
            }
            // v3 wraps the encrypted payload in another JSON string; v2 is base64 directly.
            if let Ok(raw) = B64.decode(payload.trim()) {
                report.set_crack_hash(CrackHash::new(
                    format!("$blockchain$v2${iterations}${}${}", raw.len(), hex::encode(&raw)),
                    "blockchain2john / hashcat -m 15200",
                ));
            }
            Some(report)
        }
        Ok(_) => None,
        Err(_) => parse_v1(data),
    }
}

fn base_report() -> WalletReport {
    let mut r = WalletReport::new(WalletKind::BlockchainInfo);
    r.set_encrypted(true);
    r
}

fn parse_v1(data: &[u8]) -> Option<WalletReport> {
    let compact: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let raw = B64.decode(&compact).ok()?;
    if raw.len() < 32 || raw.len() % 16 != 0 || raw.starts_with(b"Salted__") || raw.starts_with(b"BIE1") {
        return None;
    }
    let mut report = base_report();
    report.set_meta("version", json!(1));
    report.set_meta("note", json!("bare base64 blob; v1 format inferred, not confirmed"));
    report.set_crack_hash(CrackHash::new(
        format!("$blockchain${}${}", raw.len(), hex::encode(&raw)),
        "blockchain2john / hashcat -m 12700",
    ));
    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_envelope() {
        let payload = B64.encode([5u8; 48]);
        let text = format!(r#"{{"guid":"abc","payload":"{payload}","pbkdf2_iterations":5000,"version":2}}"#);
        assert!(looks_like(text.as_bytes()));
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.crack_hash().unwrap().hash(), format!("$blockchain$v2$5000$48${}", "05".repeat(48)));
    }

    #[test]
    fn v1_blob() {
        let r = parse(B64.encode([1u8; 64]).as_bytes()).unwrap();
        assert!(r.crack_hash().unwrap().hash().starts_with("$blockchain$64$"));
        assert!(parse(b"not base64 !!").is_none());
    }
}
