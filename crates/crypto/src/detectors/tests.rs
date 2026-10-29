//! Cross-detector tests: planted material in noise, engine-style chunking, robustness.

use super::detectors;
use crate::keys::der::{encode, DerForm};
use crate::keys::{Network, PrivateKey, Wif};
use strata_kernel::scan::{Hit, HitCategory};

/// Deterministic xorshift noise (no RNG dependency).
pub(crate) fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn key(n: u8) -> PrivateKey {
    let mut b = [0x11u8; 32];
    b[31] = n;
    PrivateKey::from_bytes(&b).unwrap()
}

/// Engine model: overlapping chunks, hits starting in the overlap tail are dropped.
fn scan_chunked(data: &[u8], chunk: usize) -> Vec<Hit> {
    let dets = detectors();
    let overlap = dets.iter().map(|d| d.max_match()).max().unwrap();
    let mut hits = Vec::new();
    let mut start = 0usize;
    while start < data.len() {
        let end = (start + chunk + overlap).min(data.len());
        let keep_below = (start + chunk) as u64;
        let last = end == data.len();
        for d in &dets {
            let mut local = Vec::new();
            d.scan(&data[start..end], start as u64, &mut local);
            hits.extend(local.into_iter().filter(|h| last || h.offset < keep_below));
        }
        start += chunk;
    }
    hits
}

struct Planted {
    data: Vec<u8>,
    expect: Vec<(HitCategory, String, u64)>,
}

fn planted() -> Planted {
    let mut data = noise(300_000, 7);
    let mut expect = Vec::new();
    let mut put = |data: &mut Vec<u8>, at: usize, bytes: &[u8], cat: HitCategory, value: String| {
        data[at..at + bytes.len()].copy_from_slice(bytes);
        expect.push((cat, value, at as u64));
    };
    let wif = Wif::new(key(1), Network::Mainnet, true).encode();
    put(&mut data, 1000, format!(" {wif} ").as_bytes(), HitCategory::PrivateKey, wif.clone());
    let wif_u = Wif::new(key(2), Network::Mainnet, false).encode();
    put(&mut data, 40_001, &utf16le(&format!(" {wif_u} ")), HitCategory::PrivateKey, wif_u.clone());
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    put(&mut data, 65_530, format!("\n{xprv}\n").as_bytes(), HitCategory::ExtendedKey, xprv.into());
    let der = encode(&key(3), DerForm::ExplicitUncompressed);
    put(&mut data, 90_000, &der, HitCategory::PrivateKey, key(3).to_hex());
    let hex_key = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    let hex = format!("bitcoin private key:\n{hex_key}\n");
    put(&mut data, 120_000, hex.as_bytes(), HitCategory::PrivateKey, hex_key.into());
    put(&mut data, 150_000, b" SzavMBLoXU6kDrqtUVmffv ", HitCategory::PrivateKey, "SzavMBLoXU6kDrqtUVmffv".into());
    let addr = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    put(&mut data, 200_000, &utf16le(&format!(" {addr} ")), HitCategory::Address, addr.into());
    let phrase = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    put(&mut data, 230_000, format!("\n{phrase}\n").as_bytes(), HitCategory::Mnemonic, phrase.into());
    Planted { data, expect }
}

#[test]
fn finds_planted_material_across_chunk_sizes() {
    let p = planted();
    for chunk in [p.data.len(), 65_536, 10_007] {
        let hits = scan_chunked(&p.data, chunk);
        for (cat, value, near) in &p.expect {
            let found: Vec<_> = hits.iter().filter(|h| h.category == *cat && &h.value == value).collect();
            assert_eq!(found.len(), 1, "chunk {chunk}: {cat:?} {value} found {}", found.len());
            assert!(found[0].offset >= *near && found[0].offset < near + 32, "offset {}", found[0].offset);
        }
    }
}

#[test]
fn noise_produces_no_key_hits() {
    let data = noise(4 << 20, 99);
    let hits = scan_chunked(&data, 1 << 20);
    let keys: Vec<_> = hits.iter().filter(|h| h.category != HitCategory::Marker).collect();
    assert!(keys.is_empty(), "{:?}", keys.first().map(|h| (&h.detector, &h.value)));
}

#[test]
fn hostile_inputs_never_panic() {
    let dets = detectors();
    let mut inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff; 7],
        b"\x02\x01\x01\x04\x20".to_vec(),
        b"0\x74\x02\x01\x01\x04\x20".to_vec(),
        b"bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_vec(),
        "abandon ".repeat(200).into_bytes(),
        "の ".repeat(3000).into_bytes(),
        vec![b'1'; 5000],
        vec![b'a'; 5000],
    ];
    let mut meta = super::bdb::synthetic_meta(4096, u32::MAX);
    meta.truncate(600);
    inputs.push(meta);
    for i in 0..64u64 {
        inputs.push(noise(1 + (i as usize * 997) % 9000, i + 1));
    }
    for input in &inputs {
        for d in &dets {
            let mut out = Vec::new();
            d.scan(input, u64::MAX - 10, &mut out);
            for cut in [1, 2, 3, 511, 513] {
                if input.len() > cut {
                    d.scan(&input[cut..], 0, &mut out);
                    d.scan(&input[..input.len() - cut], 0, &mut out);
                }
            }
        }
    }
}

#[test]
fn ids_are_unique() {
    let dets = detectors();
    let mut ids: Vec<_> = dets.iter().map(|d| d.id()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), dets.len());
    assert!(dets.iter().all(|d| d.max_match() > 0));
}
