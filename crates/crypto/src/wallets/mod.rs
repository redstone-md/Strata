//! Wallet file parsers. Each takes a whole file's bytes and returns a best-effort
//! [`WalletReport`] with [`strata_kernel::Damage`] notes; none of them panic on input.

pub mod armory;
pub mod bdb;
pub mod bitcoin_core;
pub mod blockchain_info;
mod cursor;
pub mod electrum;
pub mod multibit;
mod names;
pub mod records;
mod report;

pub use bitcoin_core::MasterKey;
pub use names::{WalletFileName, WalletNameKind};
pub use report::{CrackHash, RecoveredKey, WalletKind, WalletReport};

/// Sniff the format of a wallet file and parse it. `None` when nothing wallet-like is found.
pub fn analyze(data: &[u8]) -> Option<WalletReport> {
    if armory::looks_like(data) {
        return armory::parse(data);
    }
    if bdb::MetaPage::parse(data).is_some() {
        return bitcoin_core::parse(data);
    }
    if multibit::looks_like(data) {
        return multibit::parse(data);
    }
    if electrum::looks_like(data) {
        return electrum::parse(data);
    }
    if blockchain_info::looks_like(data) {
        return blockchain_info::parse(data);
    }
    // Headless/damaged Berkeley DB that still carries wallet records.
    let has_records = [b"\x04ckey".as_slice(), b"\x04mkey", b"\x03key"]
        .iter()
        .any(|p| memchr::memmem::find(data, p).is_some());
    if has_records && data.len() >= 512 {
        return bitcoin_core::salvage(data);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, mut seed: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect()
    }

    #[test]
    fn random_and_truncated_inputs_never_panic() {
        let mut samples: Vec<Vec<u8>> = (0..64).map(|i| noise(i * 97, i as u64 + 1)).collect();
        let mut with_magic = noise(8192, 99);
        with_magic[12..16].copy_from_slice(&[0x62, 0x31, 0x05, 0x00]);
        with_magic[20..24].copy_from_slice(&4096u32.to_le_bytes());
        with_magic[16..20].copy_from_slice(&9u32.to_le_bytes());
        samples.push(with_magic);
        let mut prefixed = armory::FILE_ID.to_vec();
        prefixed.extend(noise(50, 3));
        samples.push(prefixed);
        samples.push(b"{\"seed_version\": 4, \"seed\": 5}".to_vec());
        samples.push(b"{'seed_version': 'x', 'keystore': {'xprv': 'zz', 'seed': 7}}".to_vec());
        samples.push(b"U2FsdGVkX1".to_vec());
        samples.push(b"QklFMQ==".to_vec());
        samples.push(b"{\"payload\": 1, \"guid\": 2}".to_vec());
        let mut ckey = noise(4096, 5);
        ckey[100..105].copy_from_slice(b"\x04ckey");
        samples.push(ckey);
        for s in &samples {
            for cut in [0, 1.min(s.len()), s.len() / 3, s.len() / 2, s.len()] {
                let _ = analyze(&s[..cut]);
                let _ = bitcoin_core::salvage(&s[..cut]);
                let _ = electrum::parse(&s[..cut]);
                let _ = multibit::parse(&s[..cut]);
                let _ = blockchain_info::parse(&s[..cut]);
                let _ = armory::parse(&s[..cut]);
            }
        }
    }

    #[test]
    fn analyze_dispatches() {
        let text = "# KEEP YOUR PRIVATE KEYS SAFE\nKwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn 2013\n";
        let r = analyze(text.as_bytes()).unwrap();
        assert_eq!(r.kind(), WalletKind::MultiBitClassic);
        assert!(r.to_json().get("keys").is_some());
        assert!(analyze(b"hello world").is_none());
    }
}
