//! Electrum wallet files: 1.x dict files, 2.x+ JSON keystores and fully encrypted (BIE1) files.

use super::report::{CrackHash, RecoveredKey, WalletKind, WalletReport};
use crate::keys::bip32::{DerivationPlan, ExtendedKey};
use crate::keys::mnemonic::{ElectrumSeed, OldElectrum};
use crate::keys::Wif;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};

/// Base64 of `BIE1`, the prefix of a fully encrypted Electrum wallet file.
pub const BIE1_PREFIX: &[u8] = b"QklFMQ";
/// Addresses derived from plain seeds/xprvs.
const DERIVE_COUNT: u32 = 5;

/// Sniff: BIE1 blob or a JSON/dict object with Electrum keys.
pub fn looks_like(data: &[u8]) -> bool {
    let text = trim(data);
    text.starts_with(BIE1_PREFIX)
        || (text.starts_with(b"{")
            && ["seed_version", "keystore", "wallet_type"]
                .iter()
                .any(|k| memchr::memmem::find(text, k.as_bytes()).is_some()))
}

fn trim(data: &[u8]) -> &[u8] {
    let data = data.strip_prefix(b"\xef\xbb\xbf".as_slice()).unwrap_or(data);
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    let end = data.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |e| e + 1);
    data.get(start..end).unwrap_or(&[])
}

pub fn parse(data: &[u8]) -> Option<WalletReport> {
    let text = trim(data);
    if text.starts_with(BIE1_PREFIX) {
        return Some(parse_bie1(text));
    }
    let obj = parse_object(text)?;
    if !["seed_version", "keystore", "wallet_type", "keypairs"].iter().any(|k| obj.contains_key(*k)) {
        return None;
    }
    let mut report = WalletReport::new(WalletKind::Electrum);
    for k in ["seed_version", "wallet_type", "use_encryption"] {
        if let Some(v) = obj.get(k) {
            report.set_meta(k, v.clone());
        }
    }
    let encrypted = obj.get("use_encryption").and_then(Value::as_bool).unwrap_or(false);
    report.set_encrypted(encrypted);
    if let Some(seed) = obj.get("seed").and_then(Value::as_str) {
        v1_seed(seed, encrypted, &mut report);
    }
    if let Some(ks) = obj.get("keystore").and_then(Value::as_object) {
        keystore(ks, &mut report);
    }
    for (k, v) in &obj {
        if k.starts_with('x') && k.ends_with('/')
            && let Some(ks) = v.as_object() {
                keystore(ks, &mut report);
            }
    }
    if let Some(kp) = obj.get("keypairs").and_then(Value::as_object) {
        keypairs(kp, &mut report);
    }
    addresses(obj.get("addresses"), &mut report);
    if let Some(labels) = obj.get("labels").and_then(Value::as_object) {
        for (addr, label) in labels {
            if let Some(l) = label.as_str() {
                report.add_label(addr, l);
            }
        }
    }
    Some(report)
}

/// JSON, or an Electrum 1.x Python dict literal (single quotes, True/False/None).
fn parse_object(text: &[u8]) -> Option<Map<String, Value>> {
    if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(text) {
        return Some(m);
    }
    let s = std::str::from_utf8(text).ok()?;
    let fixed = s.replace('\'', "\"").replace("True", "true").replace("False", "false").replace("None", "null");
    match serde_json::from_str::<Value>(&fixed) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn parse_bie1(text: &[u8]) -> WalletReport {
    let mut report = WalletReport::new(WalletKind::Electrum);
    report.set_encrypted(true);
    report.set_meta("file_encryption", json!("BIE1"));
    let compact: Vec<u8> = text.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if let Ok(raw) = B64.decode(&compact) {
        // BIE1 || ephemeral pubkey (33) || ciphertext || mac (32)
        if let (Some(pk), Some(ct), Some(mac)) = (
            raw.get(4..37),
            raw.get(37..raw.len().saturating_sub(32)),
            raw.get(raw.len().saturating_sub(32)..),
        )
            && !ct.is_empty() {
                report.set_crack_hash(CrackHash::new(
                    format!("$electrum$5*{}*{}*{}", hex::encode(pk), hex::encode(ct), hex::encode(mac)),
                    "hashcat -m 21800 (verify with electrum2john)",
                ));
            }
    }
    report
}

fn v1_seed(seed: &str, encrypted: bool, report: &mut WalletReport) {
    let is_hex = seed.len() == 32 && seed.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex && !encrypted {
        report.set_meta("seed_hex", json!(seed));
        for a in OldElectrum::from_hex_seed(seed).addresses(DERIVE_COUNT) {
            if let Some(w) = Wif::parse(a.wif.as_bytes()) {
                report.add_key(RecoveredKey::plain(format!("seed {}", a.path), *w.key(), w.compressed(), w.network()));
            }
        }
    } else if let Ok(raw) = B64.decode(seed)
        && let (Some(iv), Some(ct)) = (raw.get(..16), raw.get(16..32)) {
            report.set_crack_hash(CrackHash::new(
                format!("$electrum$1*{}*{}", hex::encode(iv), hex::encode(ct)),
                "hashcat -m 16600 (verify with electrum2john)",
            ));
        }
}

fn keystore(ks: &Map<String, Value>, report: &mut WalletReport) {
    let s = |k: &str| ks.get(k).and_then(Value::as_str);
    if let Some(t) = s("type") {
        report.set_meta("keystore_type", json!(t));
    }
    if let Some(xpub) = s("xpub").or(s("mpk")) {
        report.set_meta("xpub", json!(xpub));
    }
    if let Some(xprv) = s("xprv") {
        match ExtendedKey::parse(xprv.as_bytes()) {
            Some(key) => {
                report.set_meta("xprv", json!(xprv));
                for d in DerivationPlan::new(DERIVE_COUNT).derive(&key) {
                    if let Some(w) = d.wif().and_then(|w| Wif::parse(w.as_bytes())) {
                        report.add_key(RecoveredKey::plain(format!("xprv {}", d.path()), *w.key(), true, w.network()));
                    }
                    report.add_address(d.address());
                }
            }
            None => encrypted_blob(xprv, s("xpub").is_some_and(|x| x.starts_with('x')), report),
        }
    }
    if let Some(seed) = s("seed") {
        match ElectrumSeed::detect(seed) {
            Some(es) => {
                report.set_meta("seed", json!(seed));
                report.set_meta("seed_type", json!(es.kind().name()));
                let pass = s("passphrase").unwrap_or("");
                for a in es.addresses(pass, DERIVE_COUNT) {
                    if let Some(w) = Wif::parse(a.wif.as_bytes()) {
                        report.add_key(RecoveredKey::plain(format!("seed {}", a.path), *w.key(), w.compressed(), w.network()));
                    }
                }
            }
            None if seed.contains(' ') => report.set_meta("seed", json!(seed)),
            None => {
                if s("xprv").is_none() {
                    encrypted_blob(seed, true, report);
                }
            }
        }
    }
    if let Some(kp) = ks.get("keypairs").and_then(Value::as_object) {
        keypairs(kp, report);
    }
}

/// Encrypted keystore field (base64 iv||ct): Electrum 2.x hash.
fn encrypted_blob(blob: &str, legacy_xprv: bool, report: &mut WalletReport) {
    if let Ok(raw) = B64.decode(blob)
        && let (Some(iv), Some(ct)) = (raw.get(..16), raw.get(16..32)) {
            let salt_type = if legacy_xprv { 2 } else { 3 };
            report.set_crack_hash(CrackHash::new(
                format!("$electrum${salt_type}*{}*{}", hex::encode(iv), hex::encode(ct)),
                "hashcat -m 16600 (verify with electrum2john)",
            ));
        }
}

fn keypairs(kp: &Map<String, Value>, report: &mut WalletReport) {
    for (pubkey, secret) in kp {
        let Some(secret) = secret.as_str() else { continue };
        let wif_text = secret.rsplit(':').next().unwrap_or(secret);
        match Wif::parse(wif_text.as_bytes()) {
            Some(w) => report.add_key(RecoveredKey::plain("keypairs", *w.key(), w.compressed(), w.network())),
            None => {
                let pk = hex::decode(pubkey).unwrap_or_default();
                let ct = B64.decode(secret).ok();
                report.add_key(RecoveredKey::public("keypairs", &pk, ct.as_deref()));
                encrypted_blob(secret, true, report);
            }
        }
    }
}

fn addresses(v: Option<&Value>, report: &mut WalletReport) {
    match v {
        Some(Value::String(s)) => report.add_address(s),
        Some(Value::Array(a)) => a.iter().for_each(|x| addresses(Some(x), report)),
        Some(Value::Object(o)) => o.iter().for_each(|(k, x)| {
            if matches!(x, Value::Array(_) | Value::Object(_)) {
                addresses(Some(x), report);
            } else if k.len() >= 26 {
                report.add_address(k);
            }
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    #[test]
    fn v1_plain_seed_dict() {
        let text = "{'seed_version': 4, 'use_encryption': False, 'seed': '0123456789abcdef0123456789abcdef', 'labels': {}}";
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.encrypted(), Some(false));
        assert_eq!(r.plain_key_count(), DERIVE_COUNT as usize);
    }

    #[test]
    fn v1_encrypted_seed_hash() {
        let blob = B64.encode([7u8; 64]);
        let text = format!("{{\"seed_version\": 4, \"use_encryption\": true, \"seed\": \"{blob}\"}}");
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.crack_hash().unwrap().hash(), format!("$electrum$1*{}*{}", "07".repeat(16), "07".repeat(16)));
    }

    #[test]
    fn keystore_xprv() {
        let text = format!(r#"{{"seed_version": 18, "wallet_type": "standard", "use_encryption": false,
            "keystore": {{"type": "bip32", "xprv": "{XPRV}", "xpub": "xpub..."}},
            "addresses": {{"receiving": ["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"], "change": []}}}}"#);
        let r = parse(text.as_bytes()).unwrap();
        assert!(r.plain_key_count() > 0);
        assert!(r.addresses().iter().any(|a| a == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
        assert_eq!(r.metadata().get("xprv"), Some(&json!(XPRV)));
    }

    #[test]
    fn bie1_blob() {
        let mut raw = b"BIE1".to_vec();
        raw.extend([2u8; 33]);
        raw.extend([9u8; 48]);
        raw.extend([1u8; 32]);
        let text = B64.encode(&raw);
        assert!(looks_like(text.as_bytes()));
        let r = parse(text.as_bytes()).unwrap();
        assert_eq!(r.encrypted(), Some(true));
        assert!(r.crack_hash().unwrap().hash().starts_with("$electrum$5*0202"));
    }
}
