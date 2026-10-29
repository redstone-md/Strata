//! `cargo run -p strata-volume --example peek -- <image> <offset> [len]`: hex dump bytes.
fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("image");
    let off: u64 = a.next().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).expect("hex offset");
    let len: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(512);
    let disk = strata_source::open_source(&path, Some(&std::env::temp_dir())).expect("open");
    let data = disk.read_vec(off, len).expect("read");
    for (i, row) in data.chunks(16).enumerate() {
        let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
        let txt: String = row.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '.' }).collect();
        println!("{:#012x}  {:<48} {txt}", off + (i * 16) as u64, hex.join(" "));
    }
}
