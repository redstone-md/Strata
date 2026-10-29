//! Text and date helpers shared by all parsers. All of them are total (never panic).

use strata_kernel::Timestamp;
use strata_kernel::bytes;

/// UTC civil time to a timestamp. Reuses the kernel's calendar via the DOS date encoding
/// (valid for 1980..=2107), adding back the odd second DOS cannot hold.
pub fn civil(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Option<Timestamp> {
    if !(1980..=2107).contains(&y) || s > 59 {
        return None;
    }
    let date = u16::try_from(((y - 1980) << 9) | (i64::from(mo) << 5) | i64::from(d)).ok()?;
    let time = u16::try_from((h << 11) | (mi << 5) | (s / 2)).ok()?;
    let ts = Timestamp::from_dos(date, time)?;
    Timestamp::from_unix_secs(ts.unix_secs() + i64::from(s % 2))
}

/// Shift by a timezone offset in seconds (local = UTC + offset, so UTC = local − offset).
pub fn shift(ts: Timestamp, offset_secs: i64) -> Option<Timestamp> {
    Timestamp::from_unix_secs(ts.unix_secs().checked_sub(offset_secs)?)
}

fn num(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// `2012-01-31T19:57:06Z`, `2012-01-31 19:57:06`, `2012-01-31T19:57:06.890+03:00`, `20120131`.
pub fn parse_iso8601(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    if s.len() == 8 && num(s).is_some() {
        return civil(i64::from(num(&s[..4])?), num(&s[4..6])?, num(&s[6..8])?, 0, 0, 0);
    }
    let y = i64::from(num(s.get(0..4)?)?);
    let mo = num(s.get(5..7)?)?;
    let d = num(s.get(8..10)?)?;
    let rest = s.get(10..).unwrap_or("");
    if rest.is_empty() {
        return civil(y, mo, d, 0, 0, 0);
    }
    let time = rest.get(1..)?;
    let h = num(time.get(0..2)?)?;
    let mi = num(time.get(3..5)?)?;
    let sec = time.get(6..8).and_then(num).unwrap_or(0);
    let base = civil(y, mo, d, h, mi, sec)?;
    let tz = time.get(8..).unwrap_or("").trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    Some(match tz.as_bytes().first() {
        Some(b'+') | Some(b'-') => shift(base, tz_offset(tz)?)?,
        _ => base,
    })
}

/// `+0400`, `-03:00` → seconds.
fn tz_offset(tz: &str) -> Option<i64> {
    let sign = if tz.starts_with('-') { -1 } else { 1 };
    let digits: String = tz.chars().skip(1).filter(char::is_ascii_digit).collect();
    let h = i64::from(num(digits.get(0..2)?)?);
    let m = digits.get(2..4).and_then(num).map_or(0, i64::from);
    Some(sign * (h * 3600 + m * 60))
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];

/// RFC 2822 mail date: `Sat, 14 May 2011 17:36:09 +0400` (weekday optional).
pub fn parse_rfc2822(s: &str) -> Option<Timestamp> {
    let s = s.split_once(',').map_or(s, |(_, r)| r);
    let mut it = s.split_whitespace();
    let d = num(it.next()?)?;
    let mon = it.next()?.to_ascii_lowercase();
    let mo = MONTHS.iter().position(|m| mon.starts_with(m))? as u32 + 1;
    let mut y = i64::from(num(it.next()?)?);
    if y < 100 {
        y += if y < 70 { 2000 } else { 1900 };
    }
    let mut hms = it.next()?.split(':');
    let h = num(hms.next()?)?;
    let mi = num(hms.next()?)?;
    let sec = hms.next().and_then(num).unwrap_or(0);
    let base = civil(y, mo, d, h, mi, sec)?;
    match it.next() {
        Some(tz) if tz.starts_with('+') || tz.starts_with('-') => shift(base, tz_offset(tz)?),
        _ => Some(base),
    }
}

/// ROT13 over ASCII letters (UserAssist value names).
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

/// Single-byte Windows text. Cyrillic CP1251 is the common ANSI page on the target disks;
/// other high bytes fall back to Latin-1.
pub fn ansi(data: &[u8]) -> String {
    data.iter()
        .take_while(|b| **b != 0)
        .map(|&b| match b {
            0xC0..=0xFF => char::from_u32(0x0410 + u32::from(b - 0xC0)).unwrap_or('?'),
            0xA8 => 'Ё',
            0xB8 => 'ё',
            0xB9 => '№',
            _ => b as char,
        })
        .collect()
}

/// NUL-terminated ANSI string at `off`, at most `max` bytes.
pub fn ansi_at(data: &[u8], off: usize, max: usize) -> String {
    data.get(off..).map(|d| ansi(&d[..d.len().min(max)])).unwrap_or_default()
}

/// NUL-terminated UTF-16LE string at `off`, at most `max` bytes.
pub fn utf16_at(data: &[u8], off: usize, max: usize) -> String {
    data.get(off..).map(|d| bytes::utf16le(&d[..d.len().min(max)])).unwrap_or_default()
}

/// NUL-separated UTF-16LE strings (REG_MULTI_SZ, prefetch file lists); empty items dropped.
pub fn utf16_list(data: &[u8], max_items: usize) -> Vec<String> {
    let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    units.split(|u| *u == 0).filter(|s| !s.is_empty()).take(max_items).map(String::from_utf16_lossy).collect()
}

/// Windows GUID at `off` (mixed-endian) as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn guid_at(data: &[u8], off: usize) -> Option<String> {
    let raw: [u8; 16] = bytes::array(data, off)?;
    let d1 = bytes::u32_le(&raw, 0)?;
    let d2 = bytes::u16_le(&raw, 4)?;
    let d3 = bytes::u16_le(&raw, 6)?;
    let tail: String = raw[10..].iter().map(|x| format!("{x:02X}")).collect();
    Some(format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{tail}}}", raw[8], raw[9]))
}

/// FILETIME at `off` as a timestamp.
pub fn filetime_at(data: &[u8], off: usize) -> Option<Timestamp> {
    Timestamp::from_filetime(bytes::u64_le(data, off)?)
}

/// Host part of a URL (`https://user@Host:80/x` → `host`).
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?.trim_start_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Conservative e-mail shape check (`local@domain.tld`).
pub fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else { return false };
    let tld = domain.rsplit('.').next().unwrap_or("");
    !local.is_empty()
        && local.len() <= 64
        && domain.contains('.')
        && tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._%+-".contains(c))
}

/// Text that looks like a URL worth keeping.
pub fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["http://", "https://", "ftp://", "file://"].iter().any(|p| l.starts_with(p)) && s.len() > 10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(civil(2011, 5, 14, 17, 36, 9).unwrap().to_string(), "2011-05-14 17:36:09");
        assert_eq!(parse_iso8601("2012-01-31T19:57:06.890Z").unwrap().to_string(), "2012-01-31 19:57:06");
        assert_eq!(parse_iso8601("2012-01-31T22:57:06+03:00").unwrap().to_string(), "2012-01-31 19:57:06");
        assert_eq!(parse_iso8601("20110514").unwrap().to_string(), "2011-05-14 00:00:00");
        assert_eq!(parse_rfc2822("Sat, 14 May 2011 21:36:09 +0400").unwrap().to_string(), "2011-05-14 17:36:09");
        for bad in ["", "2011", "2011-13-40T99:99:99", "Sat, 99 Foo 2011", "\u{0430}\u{0431}\u{0432}\u{0433}-01"] {
            assert!(parse_iso8601(bad).is_none() && parse_rfc2822(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn strings() {
        assert_eq!(rot13("HRZR_EHACNGU"), "UEME_RUNPATH");
        assert_eq!(ansi(&[0xCF, 0xF0, 0xE8, 0, 0x41]), "При");
        assert_eq!(host_of("https://u@E.Mail.ru:443/x?y").as_deref(), Some("e.mail.ru"));
        assert!(is_email("anna.test3@mail.ru") && !is_email("a@b") && !is_email("x@y.c0m"));
        assert_eq!(utf16_at(b"a\0b\0\0\0c\0", 0, 100), "ab");
        assert_eq!(utf16_at(b"a", 5, 100), "");
    }
}
