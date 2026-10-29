//! `cargo run -p strata-fs --example walk -- <image> [volume-index] [--carve]`
//!
//! Walks the filesystem metadata of one volume (default: every volume) and prints entry counts,
//! the first paths and a sample of deleted files. Reads metadata only.

use std::collections::BTreeMap;
use std::time::Instant;
use strata_fs::{EntryState, FileSystem, FsOptions, open_filesystem_with};
use strata_volume::VolumeScanner;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let carve = args.iter().any(|a| a == "--carve");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let Some(path) = positional.first() else {
        eprintln!("usage: walk <image> [volume-index] [--carve]");
        std::process::exit(2);
    };
    let only: Option<u32> = positional.get(1).and_then(|s| s.parse().ok());
    let cache = std::env::temp_dir();
    let disk = match strata_source::open_source(path, Some(&cache)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("open {path}: {e}");
            std::process::exit(1);
        }
    };
    let options = FsOptions::default().with_record_carving(carve);
    for vol in VolumeScanner::new(512, 0).scan(disk.as_ref()) {
        if only.is_some_and(|i| i != vol.index) {
            continue;
        }
        println!("== volume {} {:?} at {} ({:?})", vol.index, vol.fs, vol.range, vol.origin);
        let started = Instant::now();
        match open_filesystem_with(vol.open(disk.clone()), vol.fs, options) {
            Ok(fs) => report(fs.as_ref(), started),
            Err(e) => println!("   not parsed: {e}"),
        }
    }
}

fn report(fs: &dyn FileSystem, started: Instant) {
    let elapsed = started.elapsed();
    let entries = fs.entries();
    let count = |s: EntryState| entries.iter().filter(|e| e.state == s).count();
    let dirs = entries.iter().filter(|e| e.is_dir).count();
    let damaged = entries.iter().filter(|e| !e.damage.is_empty()).count();
    let free: u64 = fs.unallocated().iter().map(|r| r.len()).sum();
    println!("   parsed in {:.2?}: {} entries", elapsed, entries.len());
    println!(
        "   allocated {} / deleted {} / orphan {}; dirs {} / files {}",
        count(EntryState::Allocated),
        count(EntryState::Deleted),
        count(EntryState::Orphan),
        dirs,
        entries.len() - dirs
    );
    println!("   entries with damage {damaged}; metadata damage {}; unallocated {} MiB", fs.damage().len(), free >> 20);
    for d in fs.damage().iter().take(10) {
        println!("   ! {:?} {}", d.kind(), d.note());
    }
    let mut notes: BTreeMap<String, usize> = BTreeMap::new();
    for d in entries.iter().flat_map(|e| &e.damage) {
        let key: String = d.note().chars().take(60).collect();
        *notes.entry(key).or_default() += 1;
    }
    for (note, n) in &notes {
        println!("   entry damage x{n}: {note}");
    }
    println!("   -- first 40 paths");
    for e in entries.iter().filter(|e| !e.path.is_empty()).take(40) {
        println!("   {}{}", e.path, if e.is_dir { "/" } else { "" });
    }
    println!("   -- deleted files (sample)");
    let deleted = entries.iter().filter(|e| e.state != EntryState::Allocated && !e.is_dir && e.size > 0);
    for e in deleted.take(25) {
        let when = e.times.modified.map(|t| t.to_string()).unwrap_or_else(|| "-".into());
        let note = e.damage.first().map(|d| format!("  [{}]", d.note())).unwrap_or_default();
        println!("   {:?} {:>12} {}  {}{}", e.state, e.size, when, e.path, note);
    }
}
