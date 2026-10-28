//! `cargo run -p strata-volume --example probe -- <image>`: print size, damage and volumes.
use strata_volume::VolumeScanner;

fn main() {
    let path = std::env::args().nth(1).expect("usage: probe <image>");
    let cache = std::env::temp_dir();
    let disk = strata_source::open_source(&path, Some(&cache)).expect("open");
    println!("{:?}", disk.info());
    println!("damage ranges: {}", disk.damage().len());
    for v in VolumeScanner::new(512, 0).scan(disk.as_ref()) {
        println!("{v:?}");
    }
}

