//! Throughput of `SignatureDetector` over pseudo-random data (worst case for prefilters).
//!
//! `cargo run --release -p strata-identify --example detector_bench -- [MiB]`

use std::time::Instant;
use strata_identify::{SignatureDetector, testkit};
use strata_kernel::scan::{Detector, Hit};

fn run(det: &SignatureDetector, data: &[u8], label: &str) {
    let chunk = 16 << 20;
    let start = Instant::now();
    let mut hits: Vec<Hit> = Vec::new();
    for (i, c) in data.chunks(chunk).enumerate() {
        det.scan(c, (i * chunk) as u64, &mut hits);
    }
    let secs = start.elapsed().as_secs_f64();
    let mib = data.len() as f64 / (1 << 20) as f64;
    let mut kinds: Vec<String> = hits.iter().map(|h| h.details["type_id"].to_string()).collect();
    kinds.sort();
    kinds.dedup();
    println!("{label}: {mib:.0} MiB in {secs:.3}s = {:.0} MB/s, {} hits", data.len() as f64 / 1e6 / secs, hits.len());
    println!("  types: {kinds:?}");
}

fn main() {
    let mib: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let data = testkit::random(mib << 20, 42);
    run(&SignatureDetector::new(), &data, "aligned 512");
    run(&SignatureDetector::new().with_alignment(1), &data, "every byte");
}
