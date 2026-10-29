//! `cargo run --release -p strata-workbench --example detector_cost [MiB] [text%]`: single-thread
//! throughput of every catalogued detector on disk-like data (binary + text + UTF-16 text).
use std::time::Instant;
use strata_kernel::scan::Hit;
use strata_workbench::DetectorCatalog;

fn sample(mib: usize, text_share: u64) -> Vec<u8> {
    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let text = b"The quick brown fox visited http://example.com and wrote to user@example.org about the wallet. ";
    let mut out = Vec::with_capacity(mib << 20);
    while out.len() < mib << 20 {
        match next() % 100 {
            r if r < text_share / 2 => (0..40).for_each(|_| out.extend_from_slice(text)),
            r if r < text_share => (0..40).for_each(|_| out.extend(text.iter().flat_map(|b| [*b, 0]))),
            r if r % 2 == 0 => out.extend((0..4096).map(|_| next() as u8)),
            _ => out.extend(std::iter::repeat_n(0u8, 4096)),
        }
    }
    out
}

fn main() {
    let mib: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(128);
    // Second argument: percent of 4 KiB blocks that are dense text (default 5, like real disks).
    let text_share: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let data = sample(mib, text_share);
    let mut total = 0.0;
    for d in DetectorCatalog::all() {
        let start = Instant::now();
        let mut hits: Vec<Hit> = Vec::new();
        for chunk in data.chunks(16 << 20) {
            d.scan(chunk, 0, &mut hits);
        }
        let secs = start.elapsed().as_secs_f64();
        total += secs;
        println!("{:<24} {:>9.0} MB/s  {:>7} hits", d.id(), data.len() as f64 / secs / 1e6, hits.len());
    }
    println!("{:<24} {:>9.0} MB/s  (all detectors, one thread)", "combined", data.len() as f64 / total / 1e6);
}
