//! Wallet and credential containers: Bitcoin Core record markers, Electrum encrypted
//! wallets, KeePass databases.

use crate::probe::Probe;
use crate::registry::TypeId;
use memchr::memmem;
use strata_kernel::Confidence;
use strata_kernel::bytes::{u16_le, u32_le};

/// Bitcoin Core wallet record types (stored length-prefixed in both BDB and SQLite wallets).
pub const BITCOIN_RECORDS: &[&str] = &[
    "key", "ckey", "mkey", "wkey", "name", "keymeta", "defaultkey", "minversion", "version", "pool",
    "hdchain", "bestblock", "bestblock_nomerkle", "purpose", "walletdescriptor", "walletdescriptorkey",
    "walletdescriptorckey", "orderposnext", "acentry",
];

/// Records that only a Bitcoin wallet would contain (as opposed to `name`, `version`...).
const DISTINCTIVE: &[&str] = &[
    "key", "ckey", "mkey", "keymeta", "defaultkey", "minversion", "hdchain", "bestblock",
    "walletdescriptor", "walletdescriptorkey", "walletdescriptorckey",
];

/// Distinct Bitcoin Core record types present in `data`.
pub fn bitcoin_records(data: &[u8]) -> Vec<&'static str> {
    let mut needle = Vec::with_capacity(32);
    BITCOIN_RECORDS
        .iter()
        .copied()
        .filter(|name| {
            needle.clear();
            needle.push(name.len() as u8);
            needle.extend_from_slice(name.as_bytes());
            memmem::find(data, &needle).is_some()
        })
        .collect()
}

/// Is this record set convincing evidence of a Bitcoin Core wallet?
pub fn is_bitcoin_wallet(records: &[&str]) -> bool {
    records.len() >= 2 && records.iter().any(|r| DISTINCTIVE.contains(r))
}

/// Refine a BDB/SQLite probe into the matching Bitcoin Core wallet type when records agree.
pub fn refine_bitcoin(mut p: Probe, records: &[&str], confidence: Confidence) -> Probe {
    if !is_bitcoin_wallet(records) {
        if p.id == TypeId::BerkeleyDb {
            p.note("Berkeley DB: wallet.dat candidate (no Bitcoin records found in available data)");
        }
        return p;
    }
    let target = if p.id.spec().same_family(TypeId::Sqlite) { TypeId::BitcoinCoreSqlite } else { TypeId::BitcoinCoreBdb };
    p = p.refine(target).with_confidence(confidence);
    p.property("wallet_records", records.join(","));
    if records.contains(&"mkey") || records.contains(&"ckey") || records.contains(&"walletdescriptorckey") {
        p.note("wallet keys are encrypted (mkey/ckey present)");
    } else if records.contains(&"key") || records.contains(&"walletdescriptorkey") {
        p.note("unencrypted private keys present");
    }
    p
}

fn is_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

pub fn electrum_encrypted(data: &[u8]) -> Option<Probe> {
    let run = data.iter().take_while(|b| is_base64(**b)).count();
    if run < 64 && run != data.len() {
        return None;
    }
    let mut p = Probe::new(TypeId::ElectrumEncrypted, Confidence::new(0.9)).with_len(Some(run as u64));
    p.note("Electrum wallet encrypted with a password (ECIES BIE1)");
    Some(p)
}

pub fn keepass(data: &[u8]) -> Option<Probe> {
    let kdbx = data.get(4) == Some(&0x67);
    let mut p = Probe::certain(if kdbx { TypeId::KeePass2 } else { TypeId::KeePass1 });
    if kdbx {
        let major = u16_le(data, 10)?;
        if !(1..=4).contains(&major) {
            return None;
        }
        p.property("version", format!("{major}.{}", u16_le(data, 8)?));
    } else {
        p.property("flags", u32_le(data, 8)?);
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_need_distinctive_marker() {
        assert!(!is_bitcoin_wallet(&bitcoin_records(b"\x04name\x07version")));
        let recs = bitcoin_records(b"..\x04name..\x04mkey..\x04ckey..");
        assert_eq!(recs, vec!["ckey", "mkey", "name"]);
        assert!(is_bitcoin_wallet(&recs));
    }
}
