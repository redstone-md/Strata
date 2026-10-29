//! Armory `.wallet` header (PyBtcWallet): identity, labels and encryption flags.

use super::report::{WalletKind, WalletReport};
use serde_json::json;
use strata_kernel::{bytes, Damage};

pub const FILE_ID: &[u8] = b"\xbaWALLET\x00";
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const TESTNET_MAGIC: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
/// Offsets of the fixed header fields.
const VERSION: usize = 8;
const MAGIC: usize = 12;
const FLAGS: usize = 16;
const UNIQUE_ID: usize = 24;
const CREATED: usize = 30;
const SHORT_LABEL: usize = 38;
const LONG_LABEL: usize = 70;
const HEADER_END: usize = 326;

pub fn looks_like(data: &[u8]) -> bool {
    data.starts_with(FILE_ID)
}

pub fn parse(data: &[u8]) -> Option<WalletReport> {
    if !looks_like(data) {
        return None;
    }
    let mut r = WalletReport::new(WalletKind::Armory);
    if data.len() < HEADER_END {
        r.add_damage([Damage::truncated(format!("Armory header needs {HEADER_END} bytes, file has {}", data.len()))]);
    }
    if let Some(v) = bytes::u32_le(data, VERSION) {
        r.set_meta("version", json!(v));
    }
    if let Some(m) = bytes::array::<4>(data, MAGIC) {
        let net = match m {
            MAINNET_MAGIC => "mainnet",
            TESTNET_MAGIC => "testnet",
            _ => "unknown",
        };
        r.set_meta("network", json!(net));
    }
    if let Some(flags) = bytes::u64_le(data, FLAGS) {
        r.set_encrypted(flags & 1 != 0);
        r.set_meta("flags", json!(format!("{flags:016x}")));
        r.set_meta("watch_only", json!(flags & 2 != 0));
    }
    if let Some(id) = data.get(UNIQUE_ID..UNIQUE_ID + 6) {
        r.set_meta("unique_id", json!(hex::encode(id)));
    }
    if let Some(t) = bytes::u64_le(data, CREATED) {
        r.set_meta("created_unix", json!(t));
    }
    for (name, start, len) in [("label", SHORT_LABEL, 32), ("description", LONG_LABEL, 256)] {
        if let Some(raw) = data.get(start..(start + len).min(data.len())) {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            r.set_meta(name, json!(String::from_utf8_lossy(&raw[..end])));
        }
    }
    r.set_meta("note", json!("Armory KDF (ROMix) not exported; use btcrecover on the file"));
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_fields() {
        let mut d = vec![0u8; 400];
        d[..8].copy_from_slice(FILE_ID);
        d[8..12].copy_from_slice(&135u32.to_le_bytes());
        d[12..16].copy_from_slice(&MAINNET_MAGIC);
        d[16] = 1;
        d[38..44].copy_from_slice(b"Saving");
        let r = parse(&d).unwrap();
        assert_eq!(r.encrypted(), Some(true));
        assert_eq!(r.metadata().get("label"), Some(&json!("Saving")));
        assert_eq!(r.metadata().get("network"), Some(&json!("mainnet")));
        let r = parse(&d[..20]).unwrap();
        assert!(!r.damage().is_empty());
    }
}
