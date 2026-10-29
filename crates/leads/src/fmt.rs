//! Wording shared by every rule, so leads read alike.

use strata_kernel::Timestamp;

pub fn day(ts: Timestamp) -> String {
    ts.to_string().chars().take(10).collect()
}

/// `0.05 BTC`, trailing zeros trimmed.
pub fn btc(sat: u64) -> String {
    let s = format!("{:.8}", sat as f64 / 1e8);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    format!("{s} BTC")
}

/// `1BgGZ9…26SAMH`.
pub fn short_address(a: &str) -> String {
    if a.chars().count() <= 16 { a.to_string() } else { format!("{}…{}", a.chars().take(6).collect::<String>(), a.chars().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<String>()) }
}

/// When `at` happened relative to `anchor`, by calendar day.
pub fn relative(at: Timestamp, anchor: Timestamp) -> String {
    let days = (at.unix_secs().div_euclid(86_400)) - (anchor.unix_secs().div_euclid(86_400));
    match days {
        0 => "the same day".to_string(),
        1 => "the next day".to_string(),
        -1 => "the day before".to_string(),
        d if d > 0 => format!("{d} days later"),
        d => format!("{} days earlier", -d),
    }
}

/// `2011-06-14` or `2011-06-14 to 2011-08-01`.
pub fn span(a: Timestamp, b: Timestamp) -> String {
    let (x, y) = (day(a.min(b)), day(a.max(b)));
    if x == y { x } else { format!("{x} to {y}") }
}

/// Capitalise the first letter of a sentence.
pub fn sentence(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wording() {
        let t = |s| Timestamp::from_unix_secs(s).unwrap();
        assert_eq!(btc(5_000_000), "0.05 BTC");
        assert_eq!(btc(100_000_000), "1 BTC");
        assert_eq!(short_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"), "1BgGZ9…26SAMH");
        assert_eq!(relative(t(1_308_000_000), t(1_308_000_500)), "the same day");
        assert_eq!(relative(t(1_308_000_000 + 3 * 86_400), t(1_308_000_000)), "3 days later");
        assert_eq!(span(t(1_308_000_000), t(1_308_000_100)), "2011-06-13");
        assert_eq!(sentence("ran it"), "Ran it");
    }
}
