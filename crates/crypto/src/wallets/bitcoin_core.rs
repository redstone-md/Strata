//! Bitcoin Core `wallet.dat` (legacy Berkeley DB wallets): interpret BDB records.

use super::bdb::{BdbFile, BdbRecord};
use super::cursor::Cursor;
use super::records::RecordKind;
use super::report::{CrackHash, RecoveredKey, WalletKind, WalletReport};
use crate::keys::der::{DerKey, DER_CORE};
use crate::keys::Network;
use serde_json::{json, Value};

/// Encrypted master key (`CMasterKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKey {
    id: u32,
    encrypted_key: Vec<u8>,
    salt: Vec<u8>,
    method: u32,
    iterations: u32,
}

impl MasterKey {
    fn parse(id: u32, value: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(value);
        Some(Self {
            id,
            encrypted_key: c.var_bytes()?.to_vec(),
            salt: c.var_bytes()?.to_vec(),
            method: c.u32_le()?,
            iterations: c.u32_le()?,
        })
    }

    /// bitcoin2john / hashcat `-m 11300` hash string.
    pub fn crack_hash(&self) -> String {
        let ct = hex::encode(&self.encrypted_key);
        let tail = &ct[ct.len().saturating_sub(64)..];
        let salt = hex::encode(&self.salt);
        format!("$bitcoin${}${tail}${}${salt}${}$2$00$2$00", tail.len(), salt.len(), self.iterations)
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn method(&self) -> u32 {
        self.method
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "encrypted_key": hex::encode(&self.encrypted_key),
            "salt": hex::encode(&self.salt),
            "derivation_method": self.method,
            "iterations": self.iterations,
        })
    }
}

/// Parse a wallet.dat; salvage mode is used automatically when the meta page is broken.
pub fn parse(data: &[u8]) -> Option<WalletReport> {
    let db = BdbFile::parse(data)?;
    interpret(&db)
}

/// Force page salvage (ignore the meta page) for damaged files.
pub fn salvage(data: &[u8]) -> Option<WalletReport> {
    let db = BdbFile::salvage(data)?;
    interpret(&db)
}

fn interpret(db: &BdbFile) -> Option<WalletReport> {
    let mut report = WalletReport::new(WalletKind::BitcoinCore);
    let mut interp = Interpreter::default();
    for rec in db.records() {
        interp.record(rec, &mut report);
    }
    if interp.wallet_records == 0 {
        return None;
    }
    report.add_damage(db.damage().iter().cloned());
    report.set_encrypted(!interp.master_keys.is_empty() || interp.ckeys > 0);
    if let Some(mk) = interp.master_keys.first() {
        report.set_crack_hash(CrackHash::new(mk.crack_hash(), "bitcoin2john / hashcat -m 11300"));
    }
    report.set_meta("page_size", json!(db.page_size()));
    report.set_meta("endian", json!(db.endian().name()));
    report.set_meta("salvaged", json!(db.salvaged()));
    report.set_meta("record_count", json!(db.records().len()));
    report.set_meta("master_keys", Value::Array(interp.master_keys.iter().map(MasterKey::to_json).collect()));
    report.set_meta("record_types", json!(interp.counts));
    for (k, v) in interp.meta {
        report.set_meta(&k, v);
    }
    Some(report)
}

#[derive(Default)]
struct Interpreter {
    wallet_records: usize,
    ckeys: usize,
    master_keys: Vec<MasterKey>,
    counts: std::collections::BTreeMap<&'static str, usize>,
    meta: Vec<(String, Value)>,
}

impl Interpreter {
    fn record(&mut self, rec: &BdbRecord, report: &mut WalletReport) {
        let Some(kind) = RecordKind::from_key(rec.key()) else { return };
        let mut key = Cursor::new(rec.key());
        if key.var_bytes().is_none() {
            return;
        }
        self.wallet_records += 1;
        *self.counts.entry(kind.name()).or_default() += 1;
        let source = kind.name();
        let mut value = Cursor::new(rec.value());
        match kind {
            RecordKind::Key | RecordKind::WKey => {
                let pubkey = key.var_bytes().unwrap_or_default();
                let der = value.var_bytes().unwrap_or_else(|| rec.value());
                match plain_key(der, pubkey, source) {
                    Some(k) => report.add_key(k.mark_deleted(rec.deleted())),
                    None if !pubkey.is_empty() => report.add_key(RecoveredKey::public(source, pubkey, None).mark_deleted(rec.deleted())),
                    None => {}
                }
            }
            RecordKind::CKey => {
                self.ckeys += 1;
                if let Some(pubkey) = key.var_bytes() {
                    let ct = value.var_bytes();
                    report.add_key(RecoveredKey::public(source, pubkey, ct).mark_deleted(rec.deleted()));
                }
            }
            RecordKind::MKey => {
                if let Some(mk) = key.u32_le().and_then(|id| MasterKey::parse(id, rec.value())) {
                    self.master_keys.push(mk);
                }
            }
            RecordKind::Name => {
                if let (Some(addr), Some(label)) = (key.var_string(), value.var_string()) {
                    report.add_label(&addr, &label);
                }
            }
            RecordKind::Pool => {
                let pubkey = (|| {
                    value.i32_le()?;
                    value.i64_le()?;
                    value.var_bytes()
                })();
                if let Some(pk) = pubkey {
                    report.add_key(RecoveredKey::public(source, pk, None));
                }
            }
            RecordKind::DefaultKey => {
                if let Some(pk) = value.var_bytes() {
                    report.add_key(RecoveredKey::public(source, pk, None));
                }
            }
            RecordKind::HdChain => {
                let chain = (|| {
                    let version = value.i32_le()?;
                    let counter = value.u32_le()?;
                    let id = value.bytes(20)?;
                    Some(json!({"version": version, "external_counter": counter, "master_key_id": hex::encode(id)}))
                })();
                if let Some(c) = chain {
                    self.meta.push(("hdchain".into(), c));
                }
            }
            RecordKind::Version | RecordKind::MinVersion => {
                if let Some(v) = value.i32_le() {
                    self.meta.push((source.into(), json!(v)));
                }
            }
            _ => {}
        }
    }
}

/// Decode an unencrypted key record's DER privkey; falls back to locating the scalar.
fn plain_key(der: &[u8], pubkey: &[u8], source: &str) -> Option<RecoveredKey> {
    let parsed = DerKey::parse(der).or_else(|| {
        let at = memchr::memmem::find(der, DER_CORE)?;
        DerKey::parse_around_core(der, at).map(|(_, k)| k)
    });
    let (key, compressed) = match parsed {
        Some(k) => (*k.key(), k.compressed()),
        None => {
            let at = memchr::memmem::find(der, DER_CORE)?;
            let scalar = der.get(at + DER_CORE.len()..at + DER_CORE.len() + 32)?;
            (crate::keys::PrivateKey::from_slice(scalar)?, pubkey.len() == 33)
        }
    };
    let compressed = if pubkey.is_empty() { compressed } else { pubkey.len() == 33 };
    Some(RecoveredKey::plain(source, key, compressed, Network::Mainnet))
}

#[cfg(test)]
mod tests {
    use super::super::bdb::fixture::BdbBuilder;
    use super::*;
    use crate::keys::der::{encode, DerForm};
    use crate::keys::PrivateKey;

    fn var(b: &[u8]) -> Vec<u8> {
        let mut v = vec![b.len() as u8];
        v.extend_from_slice(b);
        v
    }

    fn rec_key(name: &str, rest: &[u8]) -> Vec<u8> {
        let mut k = var(name.as_bytes());
        k.extend_from_slice(rest);
        k
    }

    fn sample_wallet() -> Vec<u8> {
        let key = PrivateKey::from_hex(b"0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
        let pk = key.public_key().serialize();
        let der = encode(&key, DerForm::ExplicitCompressed);
        let mut der_val = var_long(&der);
        der_val.extend_from_slice(&[0u8; 32]);
        let mut mkey = var(&[0x11; 48]);
        mkey.extend(var(&[0x22; 8]));
        mkey.extend(0u32.to_le_bytes());
        mkey.extend(25_000u32.to_le_bytes());
        mkey.extend(var(b""));
        let mut pool = 1i32.to_le_bytes().to_vec();
        pool.extend(1_400_000_000i64.to_le_bytes());
        pool.extend(var(&pk));
        BdbBuilder::new(4096)
            .record(&rec_key("key", &var(&pk)), &der_val)
            .record(&rec_key("ckey", &var(&pk)), &var(&[0x33; 48]))
            .record(&rec_key("mkey", &1u32.to_le_bytes()), &mkey)
            .record(&rec_key("name", &var(b"1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK")), &var(b"savings"))
            .record(&rec_key("pool", &1i64.to_le_bytes()), &pool)
            .record(&rec_key("version", b""), &60000i32.to_le_bytes())
            .record(&rec_key("tx", &[0xaa; 32]), &vec![0x55; 3000])
            .build()
    }

    fn var_long(b: &[u8]) -> Vec<u8> {
        let mut v = vec![0xfd];
        v.extend((b.len() as u16).to_le_bytes());
        v.extend_from_slice(b);
        v
    }

    #[test]
    fn parses_records() {
        let r = parse(&sample_wallet()).unwrap();
        assert_eq!(r.kind(), WalletKind::BitcoinCore);
        assert_eq!(r.encrypted(), Some(true));
        assert_eq!(r.plain_key_count(), 1);
        let wif = r.keys()[0].secret().unwrap().encode();
        assert_eq!(wif, "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617");
        assert_eq!(r.labels().get("1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK").map(String::as_str), Some("savings"));
        assert_eq!(
            r.crack_hash().unwrap().hash(),
            format!("$bitcoin$64${}$16$2222222222222222$25000$2$00$2$00", "11".repeat(32))
        );
        assert_eq!(r.metadata().get("version"), Some(&json!(60000)));
        assert!(r.damage().is_empty(), "{:?}", r.damage());
    }

    #[test]
    fn salvages_damaged_wallet() {
        let mut file = sample_wallet();
        file[..64].fill(0xee);
        // Corrupt the item index of the leaf page's last entry.
        let r = parse(&file).unwrap();
        assert!(r.metadata().get("salvaged") == Some(&json!(true)));
        assert_eq!(r.plain_key_count(), 1);
        assert!(!r.damage().is_empty());
        let r = salvage(&sample_wallet()).unwrap();
        assert_eq!(r.plain_key_count(), 1);
    }

    #[test]
    fn non_wallet_bdb_is_none() {
        let file = BdbBuilder::new(4096).record(b"\x05hello", b"x").build();
        assert!(parse(&file).is_none());
    }
}
