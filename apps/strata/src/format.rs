//! Human-readable formatting shared by every view.

const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

/// `(number, unit)` for a byte count, e.g. `(650.0, "GB")`.
pub fn bytes_parts(n: u64) -> (String, &'static str) {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let text = if unit == 0 || value >= 100.0 { format!("{value:.0}") } else { format!("{value:.1}") };
    (text, UNITS[unit])
}

pub fn bytes(n: u64) -> String {
    let (v, u) = bytes_parts(n);
    format!("{v} {u}")
}

pub fn hex_offset(n: u64) -> String {
    format!("0x{n:X}")
}

pub fn percent(fraction: f32) -> String {
    format!("{:.0}%", (fraction * 100.0).clamp(0.0, 100.0))
}

/// Three-letter tile label from a path's extension (`wallet.dat` → `DAT`).
pub fn file_kind(path: &str) -> String {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && ext.len() <= 4 => ext.to_ascii_uppercase(),
        _ => "BIN".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes_and_kinds() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(650 * 1024 * 1024 * 1024), "650 GB");
        assert_eq!(file_kind(r"C:\Users\a\wallet.dat"), "DAT");
        assert_eq!(file_kind("noext"), "BIN");
        assert_eq!(hex_offset(255), "0xFF");
    }
}
