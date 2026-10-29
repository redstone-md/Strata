//! Print the identification verdict of a file as JSON.
//!
//! `cargo run -p strata-identify --example identify -- <file> [--max-mib N]`

use std::io::Read;
use strata_identify::Identifier;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: identify <file> [--max-mib N]");
        std::process::exit(2);
    };
    let max_mib: u64 = match (args.next().as_deref(), args.next()) {
        (Some("--max-mib"), Some(n)) => n.parse().unwrap_or(256),
        _ => 256,
    };
    let mut bytes = Vec::new();
    let read = std::fs::File::open(&path).and_then(|f| f.take(max_mib << 20).read_to_end(&mut bytes));
    if let Err(e) = read {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    }
    let verdict = Identifier::new().identify(&bytes, Some(&path));
    match serde_json::to_string_pretty(&verdict) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("serialize: {e}"),
    }
}
