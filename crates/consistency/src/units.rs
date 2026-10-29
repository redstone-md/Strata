//! Numbers as observations print them: sizes, shares, counts, days and spans.

use strata_kernel::Timestamp;

const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
pub(crate) const DAY_SECS: i64 = 86_400;

/// `320 GB`, `98.3 MB` (binary multiples, as the rest of Strata prints sizes).
pub(crate) fn bytes(n: u64) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value >= 100.0 { format!("{value:.0} {}", UNITS[unit]) } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// `0.03%`, `6.1%`, `58%`: enough digits that a tiny share does not print as zero.
pub(crate) fn percent(part: u64, whole: u64) -> String {
    let p = share(part, whole) * 100.0;
    if p == 0.0 || p >= 10.0 {
        format!("{p:.0}%")
    } else if p >= 1.0 {
        format!("{p:.1}%")
    } else {
        format!("{p:.2}%")
    }
}

pub(crate) fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 { 0.0 } else { part as f64 / whole as f64 }
}

/// `1,234,567`.
pub(crate) fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `2025-03-10`.
pub(crate) fn day(t: Timestamp) -> String {
    t.to_string().chars().take(10).collect()
}

/// `2012-08`.
pub(crate) fn month(t: Timestamp) -> String {
    t.to_string().chars().take(7).collect()
}

/// Whole days from `a` to `b` (negative when `b` is earlier).
pub(crate) fn days_between(a: Timestamp, b: Timestamp) -> i64 {
    (b.unix_secs() - a.unix_secs()) / DAY_SECS
}

/// `45 days`, `7 months`, `6.8 years`.
pub(crate) fn span(days: i64) -> String {
    match days {
        ..=60 => format!("{days} days"),
        61..=730 => format!("{} months", (days as f64 / 30.44).round() as i64),
        _ => format!("{:.1} years", days as f64 / 365.25),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_people_numbers() {
        assert_eq!(bytes(320_070_483_968), "298 GB");
        assert_eq!(percent(98_342_815, 320_070_483_968), "0.03%");
        assert_eq!(percent(6, 100), "6.0%");
        assert_eq!(percent(58, 100), "58%");
        assert_eq!(percent(1, 0), "0%");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(span(30), "30 days");
        assert_eq!(span(2_480), "6.8 years");
    }
}
