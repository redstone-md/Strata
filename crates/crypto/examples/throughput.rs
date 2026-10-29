//! Single-thread throughput of every crypto detector over random bytes.
//!
//! `cargo run --release -p strata-crypto --example throughput [MiB] [text]` (default 256 MiB
//! of random bytes; `text` uses English-like prose instead, the worst case for word scanning).

use std::time::Instant;
use strata_kernel::scan::Hit;

const CHUNK: usize = 16 << 20;

fn noise(len: usize) -> Vec<u8> {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
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

fn prose(len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the", "wallet", "key", "of", "and", "bitcoin", "abandon", "ability", "to", "in", "file",
        "zoo", "seed", "is", "that", "private", "network", "0x1f", "address", "label", "sent",
    ];
    let rnd = noise(len / 3 + 16);
    let mut out = Vec::with_capacity(len + 16);
    let mut i = 0;
    while out.len() < len {
        out.extend_from_slice(WORDS[rnd[i % rnd.len()] as usize % WORDS.len()].as_bytes());
        out.push(if rnd[(i + 1) % rnd.len()].is_multiple_of(13) { b'\n' } else { b' ' });
        i += 1;
    }
    out.truncate(len);
    out
}

fn main() {
    let mib: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let text = std::env::args().nth(2).is_some_and(|a| a == "text");
    let data = if text { prose(mib << 20) } else { noise(mib << 20) };
    let detectors = strata_crypto::detectors();
    let overlap = detectors.iter().map(|d| d.max_match()).max().unwrap_or(0);
    let kind = if text { "prose" } else { "random" };
    println!("{mib} MiB {kind} input, {} MiB chunks, overlap {overlap} B", CHUNK >> 20);
    let mut total_secs = 0.0;
    for d in &detectors {
        let started = Instant::now();
        let mut hits: Vec<Hit> = Vec::new();
        let mut start = 0;
        while start < data.len() {
            let end = (start + CHUNK + overlap).min(data.len());
            d.scan(&data[start..end], start as u64, &mut hits);
            start += CHUNK;
        }
        let secs = started.elapsed().as_secs_f64();
        total_secs += secs;
        println!(
            "{:<22} {:>9.0} MB/s  {:>6} hits",
            d.id(),
            data.len() as f64 / 1e6 / secs,
            hits.len()
        );
    }
    println!("{:<22} {:>9.0} MB/s  (all detectors, one thread)", "combined", data.len() as f64 / 1e6 / total_secs);
}
