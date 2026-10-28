//! Text views over raw bytes: ASCII runs as-is, UTF-16LE runs narrowed to ASCII.
//!
//! Detectors run their regex over both views and map match offsets back to raw offsets.

/// A narrowed UTF-16LE run: `text[i]` came from raw offset `start + 2 * i`.
pub struct WideRun {
    pub start: usize,
    pub text: Vec<u8>,
}

/// Extract UTF-16LE runs of printable ASCII (`c 00 c 00 ...`) at least `min_chars` long.
pub fn wide_runs(data: &[u8], min_chars: usize) -> Vec<WideRun> {
    let mut out = Vec::new();
    for parity in 0..2 {
        let mut i = parity;
        while i + 1 < data.len() {
            let start = i;
            let mut text = Vec::new();
            while i + 1 < data.len() && data[i + 1] == 0 && is_printable(data[i]) {
                text.push(data[i]);
                i += 2;
            }
            if text.len() >= min_chars {
                out.push(WideRun { start, text });
            }
            i += 2;
        }
    }
    out
}

fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}
